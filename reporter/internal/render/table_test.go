package render

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestTable_Print(t *testing.T) {
	origNoColor := noColor
	noColor = true
	defer func() { noColor = origNoColor }()

	tests := []struct {
		name     string
		table    *Table
		wantText []string
	}{
		{
			name: "basic table",
			table: &Table{
				Columns: []Column{
					{Header: "ID", Width: 4, Align: AlignLeft},
					{Header: "Name", Width: 10, Align: AlignCenter},
					{Header: "Age", Width: 3, Align: AlignRight},
				},
				Rows: [][]string{
					{"1", "Alice", "30"},
					{"2", "Bob", "25"},
					{"3", "Charlie", "35"},
				},
			},
			wantText: []string{
				"┌──────┬────────────┬─────┐",
				"│  ID  │    Name    │ Age │",
				"├──────┼────────────┼─────┤",
				"│ 1    │   Alice    │  30 │",
				"│ 2    │    Bob     │  25 │",
				"│ 3    │  Charlie   │  35 │",
				"└──────┴────────────┴─────┘",
			},
		},
		{
			name: "empty rows",
			table: &Table{
				Columns: []Column{
					{Header: "ID", Width: 4, Align: AlignLeft},
				},
				Rows: [][]string{},
			},
			wantText: []string{
				"┌──────┐",
				"│  ID  │",
				"├──────┤",
				"└──────┘",
			},
		},
		{
			name: "missing cells",
			table: &Table{
				Columns: []Column{
					{Header: "A", Width: 2, Align: AlignLeft},
					{Header: "B", Width: 2, Align: AlignLeft},
				},
				Rows: [][]string{
					{"1"}, // Missing cell for column B
				},
			},
			wantText: []string{
				"┌────┬────┐",
				"│ A  │ B  │",
				"├────┼────┤",
				"│ 1  │    │",
				"└────┴────┘",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdout to capture the table print output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Using defer here ensures os.Stdout is restored even if panic happens
			defer func() {
				w.Close()
				os.Stdout = oldStdout
			}()

			tt.table.Print()

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			io.Copy(&buf, r)

			output := buf.String()

			for _, wantText := range tt.wantText {
				if !strings.Contains(output, wantText) {
					t.Errorf("Print() output missing expected text:\nwant: %s\ngot:\n%s", wantText, output)
				}
			}
		})
	}
}
