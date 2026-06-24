// Package render provides terminal rendering utilities for compliance posture output.
// Uses ANSI escape codes and Unicode box-drawing/block characters for rich terminal display.
// Respects the NO_COLOR environment variable (https://no-color.org/).
package render

import (
	"fmt"
	"os"
)

// noColor caches the NO_COLOR check at package init.
var noColor = os.Getenv("NO_COLOR") != ""

// Green wraps text in green ANSI escape (COMPLIANT).
func Green(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[32m%s\033[0m", s)
}

// Red wraps text in red ANSI escape (NON_COMPLIANT).
func Red(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[31m%s\033[0m", s)
}

// Yellow wraps text in yellow ANSI escape (warnings, MANUAL_AUDIT).
func Yellow(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[33m%s\033[0m", s)
}

// Cyan wraps text in cyan ANSI escape (headers, labels).
func Cyan(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[36m%s\033[0m", s)
}

// Bold wraps text in bold ANSI escape.
func Bold(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[1m%s\033[0m", s)
}

// Dim wraps text in dim ANSI escape.
func Dim(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[2m%s\033[0m", s)
}

// BoldGreen combines bold and green.
func BoldGreen(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[1;32m%s\033[0m", s)
}

// BoldRed combines bold and red.
func BoldRed(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[1;31m%s\033[0m", s)
}

// BoldYellow combines bold and yellow.
func BoldYellow(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[1;33m%s\033[0m", s)
}

// BoldCyan combines bold and cyan.
func BoldCyan(s string) string {
	if noColor {
		return s
	}
	return fmt.Sprintf("\033[1;36m%s\033[0m", s)
}
