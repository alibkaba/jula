// Package main provides a standalone CLI tool for independently verifying
// the cryptographic chain of a Jula evidence pipeline run.
//
// It verifies (in order):
//  1. Manifest signature (Key A / Collector signing key)
//  2. Evidence payload hashes (SHA-256 of each file vs manifest checksums)
//  3. Provenance sidecar signatures (Key A)
//  4. Policy bundle signature (Key B / Governor signing key) [optional]
//  5. Verdict signature (Key C / Assessor signing key) [optional]
//
// This tool is designed to be run by auditors, third parties, or CI pipelines
// that need to verify evidence integrity without running the full Assessor.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/objstore"
	"github.com/alibkaba/jula-core/pkg/types"
)

func main() {
	manifestPath := flag.String("manifest", "", "Path or URL to manifest.json (gs://, s3://, file://, or local)")
	evidenceKeyEnv := flag.String("evidence-key-env", "JULA_EVIDENCE_PUBLIC_KEY", "Env var with PEM-encoded ECDSA public key for evidence/manifest verification (Key A)")
	policyKeyEnv := flag.String("policy-key-env", "JULA_POLICY_PUBLIC_KEY", "Env var with PEM-encoded ECDSA public key for policy bundle verification (Key B)")
	verdictKeyEnv := flag.String("verdict-key-env", "JULA_VERDICT_PUBLIC_KEY", "Env var with PEM-encoded ECDSA public key for verdict verification (Key C)")
	bundlePath := flag.String("bundle", "", "Path or URL to policy-bundle.json [optional]")
	verdictPath := flag.String("verdict", "", "Path or URL to verdict.json [optional]")
	flag.Parse()

	if *manifestPath == "" {
		log.Fatal("--manifest is required")
	}

	evidenceKeyPEM := os.Getenv(*evidenceKeyEnv)
	if evidenceKeyPEM == "" {
		log.Fatalf("environment variable %s is not set or empty", *evidenceKeyEnv)
	}
	evidenceKey, err := crypto.ParseECDSAPublicKey(evidenceKeyPEM)
	if err != nil {
		log.Fatalf("failed to parse evidence public key: %v", err)
	}

	result, err := verifyChain(context.Background(), verifyConfig{
		manifestPath:  *manifestPath,
		bundlePath:    *bundlePath,
		verdictPath:   *verdictPath,
		evidenceKey:   evidenceKey,
		policyKeyPEM:  os.Getenv(*policyKeyEnv),
		verdictKeyPEM: os.Getenv(*verdictKeyEnv),
	})
	if err != nil {
		log.Fatalf("verification FAILED: %v", err)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║     VERIFICATION RESULT: ALL PASSED      ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Printf("  Run ID:              %s\n", result.runID)
	fmt.Printf("  Evidence files:      %d verified\n", result.filesVerified)
	fmt.Printf("  Provenance sidecars: %d verified\n", result.provenanceVerified)
	if result.bundleVerified {
		fmt.Println("  Policy bundle:       ✓ signature valid")
	}
	if result.verdictVerified {
		fmt.Println("  Verdict:             ✓ signature valid")
	}
}

// verifyConfig holds configuration for the verification run.
type verifyConfig struct {
	manifestPath  string
	bundlePath    string
	verdictPath   string
	evidenceKey   *ecdsa.PublicKey
	policyKeyPEM  string
	verdictKeyPEM string
}

// verifyResult captures what was verified.
type verifyResult struct {
	runID                string
	filesVerified        int
	provenanceVerified   int
	bundleVerified       bool
	verdictVerified      bool
}

// verifyChain runs the full verification sequence.
func verifyChain(ctx context.Context, cfg verifyConfig) (*verifyResult, error) {
	result := &verifyResult{}

	// -----------------------------------------------------------
	// Step 1: Load and verify the manifest signature.
	// -----------------------------------------------------------
	fmt.Println("[verify] Step 1/5: Verifying manifest signature...")

	manifestData, err := readArtifact(ctx, cfg.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var manifest types.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest JSON: %w", err)
	}

	ok, err := crypto.VerifyManifest(&manifest, cfg.evidenceKey)
	if err != nil {
		return nil, fmt.Errorf("manifest signature verification error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("MANIFEST SIGNATURE IS INVALID: the manifest has been tampered with or was signed with a different key")
	}
	result.runID = manifest.RunID
	fmt.Printf("  ✓ Manifest signature valid (run_id: %s)\n", manifest.RunID)

	// -----------------------------------------------------------
	// Step 2: Verify evidence payload hashes.
	// -----------------------------------------------------------
	fmt.Printf("[verify] Step 2/5: Verifying %d evidence file hashes...\n", len(manifest.EvidenceFiles))

	// Determine the base path for reading evidence files relative to the manifest.
	manifestDir := resolveBaseDir(cfg.manifestPath)

	for _, fc := range manifest.EvidenceFiles {
		filePath := resolveRelativeTo(manifestDir, fc.Path)

		data, err := readArtifact(ctx, filePath)
		if err != nil {
			return nil, fmt.Errorf("reading evidence file %q: %w", fc.Path, err)
		}

		hash := sha256.Sum256(data)
		calculatedHash := hex.EncodeToString(hash[:])

		if calculatedHash != fc.SHA256 {
			return nil, fmt.Errorf("TAMPERING DETECTED: file %q hash mismatch (expected %s, got %s)", fc.Path, fc.SHA256, calculatedHash)
		}

		result.filesVerified++
	}
	fmt.Printf("  ✓ All %d file hashes match manifest checksums\n", result.filesVerified)

	// -----------------------------------------------------------
	// Step 3: Verify provenance sidecar signatures.
	// -----------------------------------------------------------
	fmt.Println("[verify] Step 3/5: Verifying provenance signatures...")

	for _, fc := range manifest.EvidenceFiles {
		if !strings.HasSuffix(fc.Path, ".prov.json") {
			continue
		}

		filePath := resolveRelativeTo(manifestDir, fc.Path)
		data, err := readArtifact(ctx, filePath)
		if err != nil {
			return nil, fmt.Errorf("reading provenance %q: %w", fc.Path, err)
		}

		var prov crypto.Provenance
		if err := json.Unmarshal(data, &prov); err != nil {
			return nil, fmt.Errorf("parsing provenance %q: %w", fc.Path, err)
		}

		ok, err := crypto.VerifyProvenance(&prov, cfg.evidenceKey)
		if err != nil {
			return nil, fmt.Errorf("provenance %q verification error: %w", fc.Path, err)
		}
		if !ok {
			return nil, fmt.Errorf("PROVENANCE SIGNATURE INVALID for %q: evidence provenance has been tampered with", fc.Path)
		}

		result.provenanceVerified++
	}
	fmt.Printf("  ✓ All %d provenance signatures valid\n", result.provenanceVerified)

	// -----------------------------------------------------------
	// Step 4: Verify policy bundle signature (optional).
	// -----------------------------------------------------------
	if cfg.bundlePath != "" {
		fmt.Println("[verify] Step 4/5: Verifying policy bundle signature...")

		if cfg.policyKeyPEM == "" {
			return nil, fmt.Errorf("--bundle provided but policy public key env var is empty")
		}
		policyKey, err := crypto.ParseECDSAPublicKey(cfg.policyKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing policy public key: %w", err)
		}

		bundleData, err := readArtifact(ctx, cfg.bundlePath)
		if err != nil {
			return nil, fmt.Errorf("reading policy bundle: %w", err)
		}

		var bundle crypto.PolicyBundle
		if err := json.Unmarshal(bundleData, &bundle); err != nil {
			return nil, fmt.Errorf("parsing policy bundle JSON: %w", err)
		}

		ok, err := crypto.VerifyBundle(&bundle, policyKey)
		if err != nil {
			return nil, fmt.Errorf("policy bundle verification error: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("POLICY BUNDLE SIGNATURE INVALID: policies have been tampered with or signed by a different key")
		}

		result.bundleVerified = true
		fmt.Println("  ✓ Policy bundle signature valid")
	} else {
		fmt.Println("[verify] Step 4/5: Skipping policy bundle (no --bundle provided)")
	}

	// -----------------------------------------------------------
	// Step 5: Verify verdict signature (optional).
	// -----------------------------------------------------------
	if cfg.verdictPath != "" {
		fmt.Println("[verify] Step 5/5: Verifying verdict signature...")

		if cfg.verdictKeyPEM == "" {
			return nil, fmt.Errorf("--verdict provided but verdict public key env var is empty")
		}
		verdictKey, err := crypto.ParseECDSAPublicKey(cfg.verdictKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing verdict public key: %w", err)
		}

		verdictData, err := readArtifact(ctx, cfg.verdictPath)
		if err != nil {
			return nil, fmt.Errorf("reading verdict: %w", err)
		}

		var verdict crypto.Verdict
		if err := json.Unmarshal(verdictData, &verdict); err != nil {
			return nil, fmt.Errorf("parsing verdict JSON: %w", err)
		}

		ok, err := crypto.VerifyVerdict(&verdict, verdictKey)
		if err != nil {
			return nil, fmt.Errorf("verdict verification error: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("VERDICT SIGNATURE INVALID: verdict has been tampered with or signed by a different key")
		}

		result.verdictVerified = true
		fmt.Println("  ✓ Verdict signature valid")
	} else {
		fmt.Println("[verify] Step 5/5: Skipping verdict (no --verdict provided)")
	}

	return result, nil
}

// readArtifact reads data from a local path or object store URL.
func readArtifact(ctx context.Context, path string) ([]byte, error) {
	// Check if this is a cloud URL (gs://, s3://).
	if strings.HasPrefix(path, "gs://") || strings.HasPrefix(path, "s3://") {
		store, prefix, err := objstore.FromURL(path, nil)
		if err != nil {
			return nil, fmt.Errorf("creating store for %q: %w", path, err)
		}

		// The prefix from FromURL contains everything after the bucket name.
		// Use it as the object key.
		rc, err := store.Get(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("reading from store %q: %w", path, err)
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	// Local filesystem.
	return os.ReadFile(path)
}

// resolveBaseDir returns the directory containing the manifest.
// For cloud URLs, returns the URL up to the last slash.
// For local paths, returns the parent directory.
func resolveBaseDir(manifestPath string) string {
	if strings.HasPrefix(manifestPath, "gs://") || strings.HasPrefix(manifestPath, "s3://") {
		idx := strings.LastIndex(manifestPath, "/")
		if idx > 0 {
			return manifestPath[:idx]
		}
		return manifestPath
	}
	return filepath.Dir(manifestPath)
}

// resolveRelativeTo constructs a path for an evidence file relative to the manifest's location.
// The manifest stores paths as relative keys (e.g., "deploy-abc/2026-06-23/evidence/file.json").
// If the manifest is at "/output/deploy-abc/2026-06-23/manifest.json", we resolve relative
// to "/output/" by stripping the common prefix from the evidence path.
func resolveRelativeTo(baseDir, evidencePath string) string {
	if strings.HasPrefix(baseDir, "gs://") || strings.HasPrefix(baseDir, "s3://") {
		// For cloud URLs, reconstruct the full URL from base + relative path.
		// The evidence path in the manifest is already the full object key.
		scheme := baseDir[:strings.Index(baseDir, "://")+3]
		parts := strings.SplitN(baseDir[len(scheme):], "/", 2)
		bucket := parts[0]
		return scheme + bucket + "/" + evidencePath
	}

	// For local paths, the evidence files live in the same root as the manifest's prefix dir.
	// Walk up from manifest dir to find where the evidence path's prefix starts.
	// The manifest stores keys like "deploy-abc/2026-06-23/evidence/file.json".
	// The output root is the directory above the prefix structure.
	dir := baseDir
	for {
		candidate := filepath.Join(dir, evidencePath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: try the evidence path relative to the manifest directory.
	return filepath.Join(baseDir, evidencePath)
}


