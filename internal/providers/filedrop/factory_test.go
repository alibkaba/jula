package filedrop

import (
	"context"
	"os"
	"testing"
)

func TestFactory_NewStorageReader(t *testing.T) {
	// Set a dummy AWS region so that config.LoadDefaultConfig doesn't fail
	// if there's no environment config available
	os.Setenv("JULA_AWS_REGION", "us-east-1")
	defer os.Unsetenv("JULA_AWS_REGION")

	factory := NewFactory()
	ctx := context.Background()

	tests := []struct {
		name           string
		bucketURI      string
		expectedBucket string
		expectedType   string
	}{
		{
			name:           "S3 bucket with prefix",
			bucketURI:      "s3://my-s3-bucket",
			expectedBucket: "my-s3-bucket",
			expectedType:   "*filedrop.S3Reader",
		},
		{
			name:           "GCS bucket with prefix",
			bucketURI:      "gs://my-gcs-bucket",
			expectedBucket: "my-gcs-bucket",
			expectedType:   "*filedrop.GCSReader",
		},
		{
			name:           "Bucket without prefix defaults to GCS",
			bucketURI:      "my-legacy-bucket",
			expectedBucket: "my-legacy-bucket",
			expectedType:   "*filedrop.GCSReader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, bucketName, err := factory.NewStorageReader(ctx, tt.bucketURI)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if bucketName != tt.expectedBucket {
				t.Errorf("expected bucket %q, got %q", tt.expectedBucket, bucketName)
			}

			var readerType string
			switch reader.(type) {
			case *S3Reader:
				readerType = "*filedrop.S3Reader"
			case *GCSReader:
				readerType = "*filedrop.GCSReader"
			default:
				readerType = "unknown"
			}

			if readerType != tt.expectedType {
				t.Errorf("expected reader type %q, got %q", tt.expectedType, readerType)
			}
		})
	}
}
