package render

import (
	"fmt"
	"strings"
)

// Column defines a table column with a header and width.
type Column struct {
	Header string
	Width  int
	Align  Alignment
}

// Alignment controls text alignment within a column.
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
	AlignCenter
)

// Table renders a Unicode box-drawing table to stdout.
type Table struct {
	Columns []Column
	Rows    [][]string
}

// Print renders the table to stdout with box-drawing characters.
func (t *Table) Print() {
	// Top border.
	fmt.Println("  " + t.borderLine("┌", "┬", "┐"))

	// Header row.
	fmt.Print("  │")
	for _, col := range t.Columns {
		fmt.Printf(" %s │", Bold(t.pad(col.Header, col.Width, AlignCenter)))
	}
	fmt.Println()

	// Header separator.
	fmt.Println("  " + t.borderLine("├", "┼", "┤"))

	// Data rows.
	for _, row := range t.Rows {
		fmt.Print("  │")
		for i, col := range t.Columns {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Printf(" %s │", t.pad(cell, col.Width, col.Align))
		}
		fmt.Println()
	}

	// Bottom border.
	fmt.Println("  " + t.borderLine("└", "┴", "┘"))
}

// borderLine builds a horizontal border using Unicode box chars.
func (t *Table) borderLine(left, mid, right string) string {
	var parts []string
	for _, col := range t.Columns {
		parts = append(parts, strings.Repeat("─", col.Width+2))
	}
	return left + strings.Join(parts, mid) + right
}

// pad aligns text within a fixed width. ANSI escape codes are excluded from width calculation.
func (t *Table) pad(s string, width int, align Alignment) string {
	visLen := visibleLength(s)
	if visLen >= width {
		return s
	}
	padding := width - visLen

	switch align {
	case AlignRight:
		return strings.Repeat(" ", padding) + s
	case AlignCenter:
		left := padding / 2
		right := padding - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	default: // AlignLeft
		return s + strings.Repeat(" ", padding)
	}
}

// visibleLength returns the visible length of a string, excluding ANSI escape codes.
func visibleLength(s string) int {
	inEscape := false
	count := 0
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		count++
	}
	return count
}
