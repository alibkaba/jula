package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

var (
	translatorsDir = "../../engine/translators/"
	exitFunc       = os.Exit
)

func main() {
	if err := runValidate(translatorsDir); err != nil {
		fmt.Println(err)
		exitFunc(1)
		return
	}
	fmt.Println("[SUCCESS] All translator modules passed compilation validation successfully.")
}

// runValidate performs the walk-based static analysis of Rego files under target directory.
func runValidate(dir string) error {
	fmt.Println("[VALIDATE] Initiating offline static analysis on AI patches...")
	failed := false

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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

	if err != nil {
		return err
	}
	if failed {
		return fmt.Errorf("[FATAL] Validation checks failed. Corrupted Rego code detected.")
	}
	return nil
}

