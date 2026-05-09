package filedrop

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API defines the subset of AWS S3 methods used by the reader.
type S3API interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3Reader implements StorageReader using the AWS SDK v2.
type S3Reader struct {
	BucketName string
	S3Client   S3API
}

// ListFiles returns the keys of all files under the given prefix.
func (r *S3Reader) ListFiles(ctx context.Context, prefix string) ([]string, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(r.BucketName),
		Prefix: aws.String(prefix),
	}

	result, err := r.S3Client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("listing objects in s3://%s/%s: %w", r.BucketName, prefix, err)
	}

	var keys []string
	for _, obj := range result.Contents {
		if obj.Key != nil {
			keys = append(keys, *obj.Key)
		}
	}

	return keys, nil
}

// GetFile returns the file contents as a reader, along with provider-specific metadata.
func (r *S3Reader) GetFile(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(key),
	}

	result, err := r.S3Client.GetObject(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching s3://%s/%s: %w", r.BucketName, key, err)
	}

	metadata := map[string]string{
		"content_type": aws.ToString(result.ContentType),
		"etag":         aws.ToString(result.ETag),
	}

	return result.Body, metadata, nil
}

// Ensure S3Reader satisfies the StorageReader interface.
var _ StorageReader = (*S3Reader)(nil)
