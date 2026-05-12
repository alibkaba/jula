package filedrop

import (
	"context"
	"testing"
)

func TestNewStorageReader_S3(t *testing.T) {
	t.Setenv("JULA_AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")

	f := NewFactory()
	reader, bucket, err := f.NewStorageReader(context.Background(), "s3://my-test-bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bucket != "my-test-bucket" {
		t.Errorf("expected bucket 'my-test-bucket', got '%s'", bucket)
	}

	_, ok := reader.(*S3Reader)
	if !ok {
		t.Errorf("expected *S3Reader, got %T", reader)
	}
}

func TestNewStorageReader_GCS(t *testing.T) {
	f := NewFactory()
	reader, bucket, err := f.NewStorageReader(context.Background(), "gs://my-test-bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bucket != "my-test-bucket" {
		t.Errorf("expected bucket 'my-test-bucket', got '%s'", bucket)
	}

	_, ok := reader.(*GCSReader)
	if !ok {
		t.Errorf("expected *GCSReader, got %T", reader)
	}
}

func TestNewStorageReader_DefaultGCS(t *testing.T) {
	f := NewFactory()
	reader, bucket, err := f.NewStorageReader(context.Background(), "my-test-bucket")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bucket != "my-test-bucket" {
		t.Errorf("expected bucket 'my-test-bucket', got '%s'", bucket)
	}

	_, ok := reader.(*GCSReader)
	if !ok {
		t.Errorf("expected *GCSReader, got %T", reader)
	}
}
