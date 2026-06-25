// Package main provides a minimal CLI tool for signing policy bundles.
// This is invoked by the Governor CI/CD workflow (ci-governor.yml)
// to produce a signed bundle-manifest.json sidecar.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
)

func main() {
	bundleHash := flag.String("bundle-hash", "", "SHA-256 hash of the policy bundle tarball")
	keyEnv := flag.String("key-env", "JULA_POLICY_SIGNING_KEY", "Environment variable containing the PEM-encoded ECDSA private key")
	output := flag.String("output", "bundle-manifest.json", "Output path for the signed bundle manifest")
	flag.Parse()

	if *bundleHash == "" {
		log.Fatal("--bundle-hash is required")
	}

	keyPEM := os.Getenv(*keyEnv)
	if keyPEM == "" {
		log.Fatalf("environment variable %s is not set or empty", *keyEnv)
	}

	privKey, err := crypto.ParseECDSAPrivateKey(keyPEM)
	if err != nil {
		log.Fatalf("failed to parse private key from %s: %v", *keyEnv, err)
	}

	bundle := &crypto.PolicyBundle{
		BundleHash: *bundleHash,
		Timestamp:  time.Now().UTC(),
	}

	if err := crypto.SignBundle(bundle, privKey); err != nil {
		log.Fatalf("failed to sign bundle: %v", err)
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal bundle manifest: %v", err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("failed to write bundle manifest: %v", err)
	}

	fmt.Printf("bundle-manifest.json written successfully (hash: %s)\n", *bundleHash)
}

