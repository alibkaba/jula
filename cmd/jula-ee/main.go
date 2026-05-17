package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alibkaba/jula-evidence-evaluator/internal/crypto"
	"github.com/alibkaba/jula-evidence-evaluator/internal/evaluation"
	"github.com/alibkaba/jula-evidence-evaluator/internal/ingestion"
)

func main() {
	// Parse CLI arguments.
	bucketURLFlag := flag.String("bucket-url", "", "The target GCS bucket run URL (e.g. gs://jula-evidence-ledger/2026-05-17/) or local folder path")
	policyURLFlag := flag.String("policy-url", "", "The target OPA policy directory path (e.g. ./jula-compliance-policies/policies/)")
	flag.Parse()

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
		os.Exit(1)
	}

	// Resolve the target policies URL.
	policyURL := *policyURLFlag
	if policyURL == "" {
		policyURL = os.Getenv("JULA_POLICY_URL")
	}

	if policyURL == "" {
		slog.Error("evaluator: missing policy path: please specify --policy-url flag or set JULA_POLICY_URL env variable")
		os.Exit(1)
	}

	slog.Info("evaluator: starting Jula EE assurance engine", "bucket_url", bucketURL, "policy_url", policyURL)

	// Validate the JULA_PUBLIC_KEY env variable early.
	pubKeyPEM := os.Getenv("JULA_PUBLIC_KEY")
	if pubKeyPEM == "" {
		slog.Error("evaluator: missing public key: JULA_PUBLIC_KEY environment variable is required for gatekeeper signature verification")
		os.Exit(1)
	}

	pubKey, err := crypto.ParseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		slog.Error("evaluator: failed to parse public key PEM", "error", err.Error())
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// --- Phase 1: Ingestion & The Gatekeeper ---

	// 1. Initialize the ingestion reader.
	reader := ingestion.NewGCSReader(&http.Client{Timeout: 30 * time.Second})
	if err := reader.Initialize(bucketURL); err != nil {
		slog.Error("evaluator: failed to initialize GCS downloader", "error", err.Error())
		os.Exit(1)
	}

	// 2. Download the Manifest.
	manifest, err := reader.ReadManifest(ctx, bucketURL)
	if err != nil {
		slog.Error("evaluator: failed to download manifest.json", "error", err.Error())
		os.Exit(1)
	}

	slog.Info("evaluator: downloaded manifest successfully",
		"run_id", manifest.RunID,
		"timestamp", manifest.Timestamp,
		"providers", manifest.Providers,
		"files_count", len(manifest.EvidenceFiles),
	)

	// 3. Cryptographically verify the manifest signature.
	if err := crypto.VerifyManifestSignature(manifest, pubKey); err != nil {
		slog.Error("evaluator: signature verification failed", "error", err.Error())
		os.Exit(1)
	}
	slog.Info("evaluator: manifest signature verified successfully against JULA_PUBLIC_KEY")

	// 4. Ingest raw payload files in parallel.
	payloads, err := reader.ReadPayloads(ctx, bucketURL, manifest)
	if err != nil {
		slog.Error("evaluator: failed to download evidence payloads", "error", err.Error())
		os.Exit(1)
	}

	// 5. Gatekeeper validation: verify raw content hashes against manifest checksums.
	if err := crypto.VerifyPayloads(manifest, payloads); err != nil {
		slog.Error("evaluator: GATEKEEPER FAILURE", "error", err.Error())
		os.Exit(1)
	}
	slog.Info("evaluator: Phase 1 (Ingestion & Gatekeeper) successfully and securely completed!")

	// --- Phase 2: Open Policy Agent (OPA) Evaluation ---

	// 1. Initialize OPA Evaluator.
	evaluator := evaluation.NewOPAEvaluator()

	// 2. Load policy files from target path (currently supports local paths; easily expandable).
	if err := evaluator.LoadPolicies(policyURL); err != nil {
		slog.Error("evaluator: failed to load OPA policies", "error", err.Error())
		os.Exit(1)
	}

	// 3. Compile loaded rules in memory and map ERL targets.
	if err := evaluator.Compile(ctx); err != nil {
		slog.Error("evaluator: failed to compile OPA policies", "error", err.Error())
		os.Exit(1)
	}

	// 4. Run targeted evaluation (Null-State + Rego checks).
	findings, err := evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		slog.Error("evaluator: policy evaluation error", "error", err.Error())
		os.Exit(1)
	}

	// --- Output Results ---
	slog.Info("evaluator: completed compliance evaluation", "findings_count", len(findings))

	hasFailures := false
	for _, f := range findings {
		if f.Verdict != evaluation.VerdictCompliant {
			hasFailures = true
		}
	}

	// Print standardized compliance ledger findings to stdout in formatted JSON
	fmt.Println("\n================ JULA ASSURANCE FINDINGS LEDGER ================")
	findingsJSON, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println(string(findingsJSON))
	fmt.Println("================================================================")

	if hasFailures {
		slog.Error("evaluator: compliance audit FAILED - security issues detected!")
		fmt.Println("STATUS: NON_COMPLIANT")
		os.Exit(1)
	}

	slog.Info("evaluator: compliance audit SUCCESSFUL - system is fully secure!")
	fmt.Println("STATUS: COMPLIANT")
	os.Exit(0)
}
