package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	intCrypto "github.com/alibkaba/jula-evidence-evaluator/internal/crypto"
	"github.com/alibkaba/jula-evidence-evaluator/internal/evaluation"
	"github.com/alibkaba/jula-evidence-evaluator/internal/ingestion"
	pkgCrypto "github.com/alibkaba/jula-evidence-evaluator/pkg/crypto"
	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

func main() {
	os.Exit(runApp(os.Args))
}

func runApp(args []string) int {
	fs := flag.NewFlagSet("jula", flag.ContinueOnError)
	bucketURLFlag := fs.String("bucket-url", "", "The target GCS bucket run URL (e.g. gs://jula-evidence-ledger/2026-05-17/) or local folder path")
	policyURLFlag := fs.String("policy-url", "", "The target OPA policy directory path (e.g. ./jula-compliance-policies/policies/)")

	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	// Setup logging structure.
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logHandler))

	// Resolve the target bucket URL.
	bucketURL := *bucketURLFlag
	if bucketURL == "" {
		bucketURL = os.Getenv("JULA_BUCKET_URL")
	}

	if bucketURL == "" {
		slog.Error("evaluator: missing target path: please specify --bucket-url flag or set JULA_BUCKET_URL env variable")
		return 1
	}

	// Resolve the target policies URL.
	policyURL := *policyURLFlag
	if policyURL == "" {
		policyURL = os.Getenv("JULA_POLICY_URL")
	}

	if policyURL == "" {
		slog.Error("evaluator: missing policy path: please specify --policy-url flag or set JULA_POLICY_URL env variable")
		return 1
	}

	slog.Info("evaluator: starting Jula assurance engine", "bucket_url", bucketURL, "policy_url", policyURL)

	// Validate the JULA_PUBLIC_KEY env variable early.
	pubKeyPEM := os.Getenv("JULA_PUBLIC_KEY")
	if pubKeyPEM == "" {
		slog.Error("evaluator: missing public key: JULA_PUBLIC_KEY environment variable is required for gatekeeper signature verification")
		return 1
	}

	pubKey, err := intCrypto.ParseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		slog.Error("evaluator: failed to parse public key PEM", "error", err.Error())
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// --- Phase 1: Ingestion & The Gatekeeper ---

	// 1. Initialize the ingestion reader.
	reader := ingestion.NewGCSReader(&http.Client{Timeout: 30 * time.Second})
	if err := reader.Initialize(bucketURL); err != nil {
		slog.Error("evaluator: failed to initialize GCS downloader", "error", err.Error())
		return 1
	}

	// 2. Download the Manifest.
	manifest, err := reader.ReadManifest(ctx, bucketURL)
	if err != nil {
		slog.Error("evaluator: failed to download manifest.json", "error", err.Error())
		return 1
	}

	slog.Info("evaluator: downloaded manifest successfully",
		"run_id", manifest.RunID,
		"timestamp", manifest.Timestamp,
		"providers", manifest.Providers,
		"files_count", len(manifest.EvidenceFiles),
	)

	// 3. Cryptographically verify the manifest signature.
	if err := intCrypto.VerifyManifestSignature(manifest, pubKey); err != nil {
		slog.Error("evaluator: signature verification failed", "error", err.Error())
		return 1
	}
	slog.Info("evaluator: manifest signature verified successfully against JULA_PUBLIC_KEY")

	// --- Phase 2: Open Policy Agent (OPA) Setup ---

	// 1. Initialize OPA Evaluator.
	evaluator := evaluation.NewOPAEvaluator()


	// 3. Load policy files from target path.
	if err := evaluator.LoadPolicies(policyURL); err != nil {
		slog.Error("evaluator: failed to load OPA policies", "error", err.Error())
		return 1
	}

	// 4. Compile loaded rules in memory and map SCF/ERL targets.
	if err := evaluator.Compile(ctx); err != nil {
		slog.Error("evaluator: failed to compile OPA policies", "error", err.Error())
		return 1
	}

	// --- Phase 3: Sequential Evaluation Loop ---

	// Group files in manifest by their control / routing ID (SCF ID)
	scfGroups := make(map[string][]types.FileChecksum)
	for _, f := range manifest.EvidenceFiles {
		scfID := resolveScfIDFromPath(f.Path)
		if scfID == "" {
			slog.Warn("evaluator: skipping file in manifest, could not resolve SCF ID from path", "path", f.Path)
			continue
		}
		scfGroups[scfID] = append(scfGroups[scfID], f)
	}

	var allFindings []evaluation.ControlFinding

	for scfID, files := range scfGroups {
		slog.Info("evaluator: sequentially evaluating control", "scf_id", scfID, "files_count", len(files))

		// Ingest only the files for this specific control in memory
		payloads, err := reader.ReadPayloads(ctx, bucketURL, files)
		if err != nil {
			slog.Error("evaluator: failed to download evidence payloads for control", "scf_id", scfID, "error", err.Error())
			return 1
		}

		// Gatekeeper validation: verify raw content hashes against manifest checksums
		if err := intCrypto.VerifyPayloads(files, payloads); err != nil {
			slog.Error("evaluator: GATEKEEPER FAILURE - file hash mismatch", "scf_id", scfID, "error", err.Error())
			return 1
		}

		// Cryptographically verify provenance sidecars for evidence files
		for _, f := range files {
			if strings.HasSuffix(f.Path, ".prov.json") {
				continue
			}
			provPath := strings.TrimSuffix(f.Path, ".json") + ".prov.json"
			provBytes, ok := payloads[provPath]
			if !ok {
				slog.Warn("evaluator: missing provenance sidecar for evidence file", "file", f.Path)
				continue
			}
			var prov pkgCrypto.Provenance
			if err := json.Unmarshal(provBytes, &prov); err != nil {
				slog.Error("evaluator: failed to parse provenance sidecar", "file", provPath, "error", err.Error())
				return 1
			}
			okSignature, err := pkgCrypto.VerifyProvenance(&prov, pubKey)
			if err != nil || !okSignature {
				slog.Error("evaluator: provenance signature is INVALID", "file", provPath, "error", err)
				return 1
			}
			var ev types.Evidence
			if err := json.Unmarshal(payloads[f.Path], &ev); err != nil {
				slog.Error("evaluator: failed to unmarshal evidence payload for provenance check", "file", f.Path, "error", err.Error())
				return 1
			}
			if prov.PayloadHash != ev.PayloadHash {
				slog.Error("evaluator: provenance payload hash mismatch", "file", provPath, "expected", prov.PayloadHash, "actual", ev.PayloadHash)
				return 1
			}
			slog.Info("evaluator: successfully verified provenance sidecar", "file", provPath)
		}

		// Build Evidence slice for Rego evaluation
		var evList []types.Evidence
		for _, f := range files {
			if strings.HasSuffix(f.Path, ".prov.json") {
				continue
			}
			var ev types.Evidence
			if err := json.Unmarshal(payloads[f.Path], &ev); err != nil {
				slog.Error("evaluator: failed to unmarshal evidence payload", "file", f.Path, "error", err.Error())
				return 1
			}
			if ev.SCFID == "" {
				ev.SCFID = scfID
			}
			evList = append(evList, ev)
		}

		// Perform OPA evaluation for the current control
		findings, err := evaluator.EvaluateSCF(ctx, scfID, evList)
		if err != nil {
			slog.Error("evaluator: policy evaluation error for control", "scf_id", scfID, "error", err.Error())
			return 1
		}

		allFindings = append(allFindings, findings...)

		// Release memory and run GC
		payloads = nil
		evList = nil
		runtime.GC()
	}

	// --- Output Results ---
	slog.Info("evaluator: completed compliance evaluation", "findings_count", len(allFindings))

	hasFailures := false
	for _, f := range allFindings {
		if f.Verdict != evaluation.VerdictCompliant {
			hasFailures = true
		}
	}

	// Print standardized compliance ledger findings to stdout in formatted JSON
	fmt.Println("\n================ JULA ASSURANCE FINDINGS LEDGER ================")
	findingsJSON, _ := json.MarshalIndent(allFindings, "", "  ")
	fmt.Println(string(findingsJSON))
	fmt.Println("================================================================")

	if hasFailures {
		slog.Error("evaluator: compliance audit FAILED - security issues detected!")
		fmt.Println("STATUS: NON_COMPLIANT")
		return 1
	}

	slog.Info("evaluator: compliance audit SUCCESSFUL - system is fully secure!")
	fmt.Println("STATUS: COMPLIANT")
	return 0
}

func resolveScfIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "evidence" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
