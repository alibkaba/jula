// Package main implements a build-time code generator that reads OSCAL JSON
// files (Assessment Plan and Catalog) using streaming JSON parsing, and outputs
// a hardcoded Go map into internal/mappers/oscal_map.go.
//
// This tool is invoked via go:generate from internal/mappers/oscal.go.
// It runs from the internal/mappers directory and uses relative paths to
// locate the schema files under ../../schemas/oscal/.
//
// Architectural Constraints:
//   - ZERO third-party dependencies. Only Go standard library is used.
//   - Streaming-only parsing via json.NewDecoder().Token() to handle
//     multi-megabyte JSON files without loading them entirely into memory.
//   - The generated file includes a DO NOT EDIT header per Go conventions.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"text/template"
)

// ---------------------------------------------------------------------------
// Relative paths from internal/mappers/ (the go:generate working directory).
// ---------------------------------------------------------------------------
const (
	assessmentPlanPath = "../../schemas/oscal/oscal-assessment-plan-2026.1.json"
	catalogPath        = "../../schemas/oscal/oscal-catalog-2026.1.json"
	outputPath         = "oscal_map.go"
)

// OSCALMapping is the intermediate struct used during aggregation.
// It mirrors the struct defined in internal/mappers/oscal.go so the
// generated map entries are type-compatible.
type OSCALMapping struct {
	ControlID  string
	Frameworks []string
}

// ---------------------------------------------------------------------------
// main orchestrates the three-phase pipeline:
//  1. Parse Assessment Plan  -> map[erlID]controlID
//  2. Parse Catalog           -> map[controlID][]frameworks
//  3. Aggregate + generate Go source code
// ---------------------------------------------------------------------------
func main() {
	log.SetPrefix("gen_oscal: ")
	log.SetFlags(0)

	// -----------------------------------------------------------------------
	// Phase 1: Stream the Assessment Plan to build erl.id -> control-id map.
	// -----------------------------------------------------------------------
	apFile, err := os.Open(assessmentPlanPath)
	if err != nil {
		log.Fatalf("failed to open assessment plan: %v", err)
	}
	defer apFile.Close()

	erlToControl, err := parseAssessmentPlan(apFile)
	if err != nil {
		log.Fatalf("failed to parse assessment plan: %v", err)
	}
	log.Printf("parsed assessment plan: %d erl-to-control mappings", len(erlToControl))

	// -----------------------------------------------------------------------
	// Phase 2: Stream the Catalog to build control-id -> []frameworks map.
	// -----------------------------------------------------------------------
	catFile, err := os.Open(catalogPath)
	if err != nil {
		log.Fatalf("failed to open catalog: %v", err)
	}
	defer catFile.Close()

	controlToFrameworks, err := parseCatalog(catFile)
	if err != nil {
		log.Fatalf("failed to parse catalog: %v", err)
	}
	log.Printf("parsed catalog: %d control-to-framework mappings", len(controlToFrameworks))

	// -----------------------------------------------------------------------
	// Phase 3: Aggregate the two maps and generate the Go source file.
	// -----------------------------------------------------------------------
	aggregated := aggregate(erlToControl, controlToFrameworks)
	log.Printf("aggregated: %d OSCAL mappings", len(aggregated))

	if err := generateGoFile(aggregated); err != nil {
		log.Fatalf("failed to generate Go file: %v", err)
	}
	log.Printf("successfully generated %s", outputPath)
}

// ---------------------------------------------------------------------------
// parseAssessmentPlan streams the Assessment Plan JSON and extracts a map of
// erl.id -> control-id from the "activities" array.
//
// Real OSCAL envelope structure:
//   { "assessment-plan": { "local-definitions": { "activities": [ ... ] } } }
//
// Expected JSON structure inside each activity object:
//
//	{
//	  "uuid": "...",
//	  "title": "Collect: Encrypted Backup Media",
//	  "props": [{"ns": "https://scfconnect.com/oscal", "name": "erl.id", "value": "E-BCM-16"}],
//	  "related-controls": ["BCD-11.4"]
//	}
//
// Activities missing either erl.id or related-controls are skipped with a warning.
// ---------------------------------------------------------------------------
func parseAssessmentPlan(r io.Reader) (map[string]string, error) {
	dec := json.NewDecoder(r)
	result := make(map[string]string)

	// Navigate the OSCAL envelope: assessment-plan -> local-definitions -> activities.
	for _, key := range []string{"assessment-plan", "local-definitions", "activities"} {
		if err := advanceToKey(dec, key); err != nil {
			return nil, fmt.Errorf("locating %q in assessment plan: %w", key, err)
		}
	}

	// Consume the opening '[' of the activities array.
	if err := expectDelim(dec, '['); err != nil {
		return nil, fmt.Errorf("expected activities array start: %w", err)
	}

	// Iterate over each activity object in the array.
	for dec.More() {
		var activity struct {
			UUID  string `json:"uuid"`
			Title string `json:"title"`
			Props []struct {
				NS    string `json:"ns"`
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"props"`
			RelatedControls []string `json:"related-controls"`
		}

		if err := dec.Decode(&activity); err != nil {
			return nil, fmt.Errorf("decoding activity object: %w", err)
		}

		// Extract the erl.id from the props array.
		erlID := ""
		for _, p := range activity.Props {
			if p.Name == "erl.id" {
				erlID = p.Value
				break
			}
		}

		// Guard: skip activities without an erl.id prop.
		if erlID == "" {
			log.Printf("WARNING: activity %q (uuid=%s) has no erl.id prop, skipping", activity.Title, activity.UUID)
			continue
		}

		// Guard: skip activities without related-controls.
		if len(activity.RelatedControls) == 0 {
			log.Printf("WARNING: activity %q (erl.id=%s) has no related-controls, skipping", activity.Title, erlID)
			continue
		}

		// Use the first related-control as the canonical mapping.
		result[erlID] = activity.RelatedControls[0]
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// parseCatalog streams the Catalog JSON and extracts a map of
// control-id -> []string{framework names} from the nested
// groups[].controls[] structure.
//
// Expected JSON structure inside each control object:
//
//	{
//	  "id": "BCD-11.4",
//	  "title": "Encrypted Backups",
//	  "links": [
//	    {"rel": "mapped-to", "href": "#iso-27002-2022:_8.13"},
//	    {"rel": "mapped-to", "href": "#soc2_type_2:cc7.1"}
//	  ]
//	}
//
// Framework names are extracted from href by stripping the leading '#' and
// splitting on ':' to isolate the framework identifier (e.g., "iso-27002-2022").
// ---------------------------------------------------------------------------
func parseCatalog(r io.Reader) (map[string][]string, error) {
	dec := json.NewDecoder(r)
	result := make(map[string][]string)

	// Navigate the OSCAL envelope: catalog -> groups.
	for _, key := range []string{"catalog", "groups"} {
		if err := advanceToKey(dec, key); err != nil {
			return nil, fmt.Errorf("locating %q in catalog: %w", key, err)
		}
	}

	// Consume the opening '[' of the groups array.
	if err := expectDelim(dec, '['); err != nil {
		return nil, fmt.Errorf("expected groups array start: %w", err)
	}

	// Iterate over each group object.
	for dec.More() {
		if err := parseGroupForControls(dec, result); err != nil {
			return nil, fmt.Errorf("parsing group: %w", err)
		}
	}

	return result, nil
}

// parseGroupForControls handles a single group object within the "groups" array.
// It streams through the group's keys looking for a "controls" array, then
// decodes each control to extract the id and framework mappings.
func parseGroupForControls(dec *json.Decoder, result map[string][]string) error {
	// Consume the opening '{' of the group object.
	if err := expectDelim(dec, '{'); err != nil {
		return fmt.Errorf("expected group object start: %w", err)
	}

	// Stream through the group's key-value pairs.
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("reading group key: %w", err)
		}

		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected string key in group, got %T", tok)
		}

		if key == "controls" {
			// Found the controls array inside this group.
			if err := parseControlsArray(dec, result); err != nil {
				return fmt.Errorf("parsing controls array: %w", err)
			}
		} else {
			// Skip any other key's value (could be string, object, array, etc.).
			if err := skipValue(dec); err != nil {
				return fmt.Errorf("skipping group key %q value: %w", key, err)
			}
		}
	}

	// Consume the closing '}' of the group object.
	if err := expectDelim(dec, '}'); err != nil {
		return fmt.Errorf("expected group object end: %w", err)
	}

	return nil
}

// parseControlsArray iterates over the "controls" array and decodes each
// control object to extract its id and framework mappings from links.
func parseControlsArray(dec *json.Decoder, result map[string][]string) error {
	// Consume the opening '[' of the controls array.
	if err := expectDelim(dec, '['); err != nil {
		return fmt.Errorf("expected controls array start: %w", err)
	}

	for dec.More() {
		var ctrl struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Links []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"links"`
		}

		if err := dec.Decode(&ctrl); err != nil {
			return fmt.Errorf("decoding control object: %w", err)
		}

		// Guard: skip controls without an id.
		if ctrl.ID == "" {
			log.Printf("WARNING: control with title %q has no id, skipping", ctrl.Title)
			continue
		}

		// Extract unique framework names from links with rel="mapped-to".
		seen := make(map[string]bool)
		var frameworks []string
		for _, link := range ctrl.Links {
			if link.Rel != "mapped-to" {
				continue
			}
			fw := extractFramework(link.Href)
			if fw == "" {
				continue
			}
			if !seen[fw] {
				seen[fw] = true
				frameworks = append(frameworks, fw)
			}
		}

		// Sort for deterministic output in the generated code.
		sort.Strings(frameworks)

		if len(frameworks) > 0 {
			result[ctrl.ID] = frameworks
		}
	}

	// Consume the closing ']' of the controls array.
	if err := expectDelim(dec, ']'); err != nil {
		return fmt.Errorf("expected controls array end: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// extractFramework parses a framework name from an OSCAL href string.
//
// Input:  "#iso-27002-2022:_8.13"
// Output: "iso-27002-2022"
//
// Steps:
//  1. Strip the leading '#'.
//  2. Split on ':' and take the first segment.
//  3. Return empty string if the result is blank or malformed.
// ---------------------------------------------------------------------------
func extractFramework(href string) string {
	// Strip the leading '#' anchor character.
	cleaned := strings.TrimPrefix(href, "#")
	if cleaned == "" {
		return ""
	}

	// Split on ':' to separate framework name from control number.
	// e.g., "iso-27002-2022:_8.13" -> ["iso-27002-2022", "_8.13"]
	parts := strings.SplitN(cleaned, ":", 2)
	framework := strings.TrimSpace(parts[0])

	return framework
}

// ---------------------------------------------------------------------------
// aggregate combines the erl-to-control map and the control-to-frameworks map
// into a single map keyed by erl.id.
// ---------------------------------------------------------------------------
func aggregate(erlToControl map[string]string, controlToFrameworks map[string][]string) map[string]OSCALMapping {
	result := make(map[string]OSCALMapping, len(erlToControl))

	for erlID, controlID := range erlToControl {
		frameworks := controlToFrameworks[controlID]
		if frameworks == nil {
			log.Printf("WARNING: erl.id %q -> control %q has no framework mappings in catalog", erlID, controlID)
			// Still include the mapping with an empty frameworks slice so the
			// control-id relationship is preserved in the generated code.
			frameworks = []string{}
		}

		result[erlID] = OSCALMapping{
			ControlID:  controlID,
			Frameworks: frameworks,
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// generateGoFile renders the aggregated map into a valid Go source file using
// text/template. The output includes the mandatory DO NOT EDIT header.
// ---------------------------------------------------------------------------
func generateGoFile(mappings map[string]OSCALMapping) error {
	// Sort the keys for deterministic, diff-friendly output.
	keys := make([]string, 0, len(mappings))
	for k := range mappings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build ordered entries for the template.
	type entry struct {
		ERLID      string
		ControlID  string
		Frameworks []string
	}
	entries := make([]entry, 0, len(keys))
	for _, k := range keys {
		m := mappings[k]
		entries = append(entries, entry{
			ERLID:      k,
			ControlID:  m.ControlID,
			Frameworks: m.Frameworks,
		})
	}

	// Define the Go source template.
	const tmplText = `// Code generated by tools/gen_oscal. DO NOT EDIT.

package mappers

// oscalMap is the build-time generated mapping of ERL IDs to their
// corresponding SCF control identifiers and mapped compliance frameworks.
// This map is populated by tools/gen_oscal/main.go during go:generate.
var oscalMap = map[string]OSCALMapping{
{{- range .}}
	"{{.ERLID}}": {
		ControlID:  "{{.ControlID}}",
		Frameworks: []string{ {{- range $i, $fw := .Frameworks}}{{if $i}}, {{end}}"{{$fw}}"{{end -}} },
	},
{{- end}}
}
`

	tmpl, err := template.New("oscal_map").Parse(tmplText)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file %s: %w", outputPath, err)
	}
	defer outFile.Close()

	if err := tmpl.Execute(outFile, entries); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

// ===========================================================================
// Streaming JSON Helpers
// ===========================================================================

// advanceToKey reads tokens from the decoder until it finds a JSON string
// token matching the given key name. This is used to skip to specific
// top-level or nested keys without loading the entire document.
func advanceToKey(dec *json.Decoder, key string) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return fmt.Errorf("key %q not found before EOF", key)
		}
		if err != nil {
			return fmt.Errorf("reading token while searching for key %q: %w", key, err)
		}

		// Check if this token is a string matching our target key.
		if s, ok := tok.(string); ok && s == key {
			return nil
		}
	}
}

// expectDelim consumes the next token and verifies it is the expected
// JSON delimiter (e.g., '[', ']', '{', '}').
func expectDelim(dec *json.Decoder, expected json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading delimiter: %w", err)
	}

	d, ok := tok.(json.Delim)
	if !ok || d != expected {
		return fmt.Errorf("expected delimiter %v, got %v", expected, tok)
	}
	return nil
}

// skipValue consumes and discards a single JSON value from the decoder.
// The value can be a primitive (string, number, bool, null) or a composite
// (object or array), in which case it recursively skips all nested content.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}

	// If the token is a delimiter, we need to skip the entire composite value.
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			// Skip all key-value pairs in the object.
			for dec.More() {
				// Skip the key.
				if _, err := dec.Token(); err != nil {
					return err
				}
				// Recursively skip the value.
				if err := skipValue(dec); err != nil {
					return err
				}
			}
			// Consume the closing '}'.
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			// Skip all elements in the array.
			for dec.More() {
				if err := skipValue(dec); err != nil {
					return err
				}
			}
			// Consume the closing ']'.
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
	}
	// Primitive values (string, float64, bool, nil) are already consumed
	// by the initial dec.Token() call above.

	return nil
}
