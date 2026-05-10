package filedrop

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/internal/reporter"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Factory handles the dynamic instantiation of StorageReaders based on URI schemes.
type Factory struct {
	HTTPClient *http.Client
}

// NewFactory creates a new Factory with a default HTTP client.
func NewFactory() *Factory {
	return &Factory{
		HTTPClient: &http.Client{},
	}
}

// NewStorageReader parses the bucket URI and returns the appropriate StorageReader.
// Supported schemes:
// - gs://bucket-name (GCS)
// - s3://bucket-name (S3)
// - bucket-name (Defaults to GCS for backwards compatibility)
func (f *Factory) NewStorageReader(ctx context.Context, bucketURI string) (StorageReader, string, error) {
	if strings.HasPrefix(bucketURI, "s3://") {
		bucketName := strings.TrimPrefix(bucketURI, "s3://")

		// Initialize AWS S3 Client
		awsRegion := os.Getenv("JULA_AWS_REGION")
		if awsRegion == "" {
			awsRegion = "us-east-1" // Default region
		}

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
		if err != nil {
			return nil, "", fmt.Errorf("loading aws config: %w", err)
		}

		return &S3Reader{
			BucketName: bucketName,
			S3Client:   s3.NewFromConfig(cfg),
		}, bucketName, nil
	}

	// Default to GCS (either explicit gs:// or legacy plain name)
	bucketName := strings.TrimPrefix(bucketURI, "gs://")

	tokenProvider := reporter.NewMetadataTokenProvider(f.HTTPClient)
	return &GCSReader{
		BucketName:    bucketName,
		HTTPClient:    f.HTTPClient,
		TokenProvider: tokenProvider,
	}, bucketName, nil
}
