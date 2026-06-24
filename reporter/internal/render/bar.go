package render

import (
	"fmt"
	"math"
	"strings"
)

// Bar renders a horizontal bar chart using Unicode block elements.
// value is the current value, max is the maximum value, width is the total bar width in characters.
func Bar(value, max float64, width int) string {
	if max <= 0 || width <= 0 {
		return strings.Repeat("░", width)
	}

	ratio := value / max
	if ratio > 1.0 {
		ratio = 1.0
	}

	filled := int(math.Round(ratio * float64(width)))
	empty := width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	// Color the bar based on ratio.
	if ratio >= 0.9 {
		return Green(bar)
	} else if ratio >= 0.7 {
		return Yellow(bar)
	}
	return Red(bar)
}

// BarLabeled renders a bar with a percentage label.
func BarLabeled(value, max float64, width int) string {
	pct := 0.0
	if max > 0 {
		pct = (value / max) * 100
	}
	return fmt.Sprintf("%s %3.0f%%", Bar(value, max, width), pct)
}
