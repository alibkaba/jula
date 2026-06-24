package render

import "math"

// sparkBlocks maps normalized values (0-7) to Unicode block elements.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Sparkline renders a Unicode sparkline from a slice of float64 values.
// Values are normalized to the range [min, max] of the input.
func Sparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}

	min, max := values[0], values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	spread := max - min
	if spread == 0 {
		// All values are the same; render mid-height.
		result := make([]rune, len(values))
		for i := range result {
			result[i] = sparkBlocks[3]
		}
		return string(result)
	}

	result := make([]rune, len(values))
	for i, v := range values {
		normalized := (v - min) / spread
		idx := int(math.Round(normalized * 7))
		if idx > 7 {
			idx = 7
		}
		result[i] = sparkBlocks[idx]
	}

	return string(result)
}
