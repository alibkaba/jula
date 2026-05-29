package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

const translatorsDir = "../../engine/translators/"

func main() {
	fmt.Println("[VALIDATE] Initiating offline static analysis on AI patches...")
	failed := false

	err := filepath.Walk(translatorsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".rego") {
			content, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("failed to read %s: %v\n", info.Name(), err)
				failed = true
				return nil
			}

			// Use OPA's built-in AST Compiler to validate structure locally (Zero Network Cost)
			_, err = ast.ParseModule(path, string(content))
			if err != nil {
				fmt.Printf("❌ [SYNTAX ERROR] File %s failed compilation: %v\n", info.Name(), err)
				failed = true
			} else {
				fmt.Printf("✅ [PASS] %s is syntactically sound.\n", info.Name())
			}
		}
		return nil
	})

	if err != nil || failed {
		fmt.Println("[FATAL] Validation checks failed. Corrupted Rego code detected.")
		os.Exit(1)
	}
	fmt.Println("[SUCCESS] All translator modules passed compilation validation successfully.")
}
