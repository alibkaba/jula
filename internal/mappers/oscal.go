package mappers

// ---------------------------------------------------------------------------
// OSCAL Mapper
//
// This file defines the OSCALMapping struct, the OSCALMapper interface, and
// the lookup implementation that operates against the build-time generated
// oscal_map.go file.
//
// The go:generate directive below invokes the streaming parser at
// tools/gen_oscal/main.go, which reads the OSCAL Assessment Plan and Catalog
// JSON files and emits a hardcoded map[string]OSCALMapping into oscal_map.go.
// This ensures the production binary never parses JSON at runtime.
// ---------------------------------------------------------------------------

//go:generate go run ../../tools/gen_oscal/main.go

// OSCALMapping represents the resolved relationship between an Evidence
// Request List (ERL) identifier, its corresponding SCF control, and the
// compliance frameworks that control maps to.
type OSCALMapping struct {
	// ControlID is the SCF control identifier (e.g., "BCD-11.4").
	ControlID string

	// Frameworks is the sorted list of compliance framework names this
	// control maps to (e.g., ["iso-27002-2022", "soc2_type_2"]).
	Frameworks []string
}

// OSCALMapper defines the interface for looking up OSCAL control mappings
// by Evidence Request List (ERL) identifier. This abstraction allows the
// rest of the application to consume OSCAL data without coupling to the
// generated map directly.
type OSCALMapper interface {
	// Lookup retrieves the OSCALMapping for the given ERL ID.
	// Returns the mapping and true if found, or a zero-value and false
	// if the ERL ID does not exist in the generated map.
	Lookup(erlID string) (OSCALMapping, bool)
}

// oscalMapperImpl is the concrete implementation of OSCALMapper backed by
// the build-time generated oscalMap variable in oscal_map.go.
type oscalMapperImpl struct{}

// NewOSCALMapper returns a ready-to-use OSCALMapper instance backed by the
// build-time generated map. No initialization or file loading is required.
func NewOSCALMapper() OSCALMapper {
	return &oscalMapperImpl{}
}

// Lookup retrieves the OSCALMapping for the given ERL ID from the generated
// oscalMap. It returns the mapping and true if the key exists, or a
// zero-value OSCALMapping and false if not found.
func (m *oscalMapperImpl) Lookup(erlID string) (OSCALMapping, bool) {
	mapping, ok := oscalMap[erlID]
	return mapping, ok
}
