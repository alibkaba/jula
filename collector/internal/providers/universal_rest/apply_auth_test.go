package universal_rest

import (
	"context"
	"net/http"
	"testing"
)

func TestEngine_applyAuth(t *testing.T) {
	e := NewEngine(http.DefaultClient)
	ctx := context.Background()

	tests := []struct {
		name    string
		auth    AuthFlowConfig
		setup   func(t *testing.T)
		wantErr bool
	}{
		{
			name: "unknown auth type",
			auth: AuthFlowConfig{
				Type: "unknown",
			},
			setup:   func(t *testing.T) {},
			wantErr: false,
		},
		{
			name: "aws_sigv4 missing creds",
			auth: AuthFlowConfig{
				Type: "aws_sigv4",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
		{
			name: "aws_sigv4 success",
			auth: AuthFlowConfig{
				Type: "aws_sigv4",
			},
			setup: func(t *testing.T) {
				t.Setenv("AWS_ACCESS_KEY_ID", "test")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
				t.Setenv("AWS_REGION", "us-east-1")
			},
			wantErr: false,
		},
        {
			name: "gcp_adc missing creds",
			auth: AuthFlowConfig{
				Type: "gcp_adc",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
        {
			name: "azure_identity missing creds",
			auth: AuthFlowConfig{
				Type: "azure_identity",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
        {
			name: "oci_cavage missing creds",
			auth: AuthFlowConfig{
				Type: "oci_cavage",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
        {
			name: "ali_tencent_hmac missing creds",
			auth: AuthFlowConfig{
				Type: "ali_tencent_hmac",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
        {
			name: "jws_financial missing creds",
			auth: AuthFlowConfig{
				Type: "jws_financial",
			},
			setup:   func(t *testing.T) {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			// Create a fresh request for each subtest to avoid state pollution
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)

			err := e.applyAuth(ctx, req, &tt.auth, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
