package engine

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestMergeFindingsGroup(t *testing.T) {
	tests := []struct {
		name    string
		group   []types.Finding
		want    types.Finding
		wantErr bool
	}{
		{
			name: "single finding",
			group: []types.Finding{
				{EvidenceID: "1", RawData: []byte(`[{"id": 1}]`)},
			},
			want:    types.Finding{EvidenceID: "1", RawData: []byte(`[{"id": 1}]`)},
			wantErr: false,
		},
		{
			name: "merge valid JSON arrays",
			group: []types.Finding{
				{EvidenceID: "1", RawData: []byte(`[{"id": 1}]`)},
				{EvidenceID: "1", RawData: []byte(`[{"id": 2}]`)},
			},
			want:    types.Finding{EvidenceID: "1", RawData: []byte(`[{"id":1},{"id":2}]`)},
			wantErr: false,
		},
		{
			name: "not all JSON arrays",
			group: []types.Finding{
				{EvidenceID: "1", RawData: []byte(`[{"id": 1}]`)},
				{EvidenceID: "1", RawData: []byte(`{"id": 2}`)},
			},
			want:    types.Finding{EvidenceID: "1", RawData: []byte(`{"id": 2}`)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeFindingsGroup(tt.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("mergeFindingsGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if tt.want.EvidenceID != got.EvidenceID {
					t.Errorf("mergeFindingsGroup() EvidenceID = %v, want %v", got.EvidenceID, tt.want.EvidenceID)
				}

				var wantObj, gotObj interface{}
				json.Unmarshal(tt.want.RawData, &wantObj)
				json.Unmarshal(got.RawData, &gotObj)

				if !reflect.DeepEqual(wantObj, gotObj) {
					t.Errorf("mergeFindingsGroup() RawData = %s, want %s", got.RawData, tt.want.RawData)
				}
			}
		})
	}
}
