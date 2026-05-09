package filedrop

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// mockS3Client implements S3API for testing.
type mockS3Client struct {
	objects map[string]string
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	var contents []types.Object
	prefix := *params.Prefix
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			contents = append(contents, types.Object{Key: aws.String(k)})
		}
	}
	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	content, ok := m.objects[*params.Key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &s3.GetObjectOutput{
		Body:        io.NopCloser(strings.NewReader(content)),
		ContentType: aws.String("application/json"),
		ETag:        aws.String("test-etag"),
	}, nil
}

func TestS3Reader_ListFiles(t *testing.T) {
	mock := &mockS3Client{
		objects: map[string]string{
			"prefix/file1.json": "{}",
			"prefix/file2.txt":  "hello",
			"other/file3.json":  "{}",
		},
	}
	reader := &S3Reader{
		BucketName: "test-bucket",
		S3Client:   mock,
	}

	keys, err := reader.ListFiles(context.Background(), "prefix/")
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestS3Reader_GetFile(t *testing.T) {
	content := `{"status": "PASS"}`
	mock := &mockS3Client{
		objects: map[string]string{
			"prefix/file1.json": content,
		},
	}
	reader := &S3Reader{
		BucketName: "test-bucket",
		S3Client:   mock,
	}

	body, metadata, err := reader.GetFile(context.Background(), "prefix/file1.json")
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}
	defer body.Close()

	data, _ := io.ReadAll(body)
	if string(data) != content {
		t.Errorf("expected content %s, got %s", content, string(data))
	}

	if metadata["content_type"] != "application/json" {
		t.Errorf("expected content_type application/json, got %s", metadata["content_type"])
	}
}
