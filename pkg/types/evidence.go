package types

// Evidence represents a Finding that has been mapped to a compliance framework.
type Evidence struct {
	Finding       Finding  `json:"finding"`
	Framework     string   `json:"framework"`
	Criteria      []string `json:"criteria"`
	ControlType   string   `json:"control_type"`
	MappingRuleID string   `json:"mapping_rule_id"`
}
