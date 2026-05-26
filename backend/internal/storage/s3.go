// Package storage provides the S3/R2 client wrapper for EphemeralShare.
// It wraps the AWS SDK v2 S3 client with application-specific methods for
// presigned URL generation, object head checks, and deletion.
//
// Cloudflare R2 compatibility is achieved via a custom endpoint resolver that
// overrides the default AWS endpoint with the configured S3_ENDPOINT.
package storage

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyendpoints "github.com/aws/smithy-go/endpoints"

	"ephemeral-share/backend/internal/config"
)

// ErrSSRFEndpointMismatch is returned when a generated presigned URL's host
// does not match the configured S3 endpoint host. This prevents SSRF attacks
// via misconfigured or tampered endpoint settings.
var ErrSSRFEndpointMismatch = errors.New("presigned URL host does not match configured S3 endpoint")

// S3Client wraps the AWS SDK v2 S3 client and presign client with
// application-specific methods for EphemeralShare.
type S3Client struct {
	client       *s3.Client
	presign      *s3.PresignClient
	bucket       string
	endpointHost string // parsed host from cfg.S3Endpoint for SSRF validation
}

// r2EndpointResolver implements aws.EndpointResolverWithOptions to override
// the default AWS endpoint with a custom URL (required for Cloudflare R2 and
// other S3-compatible providers).
type r2EndpointResolver struct {
	endpoint string
}

// ResolveEndpoint satisfies the smithy EndpointResolverV2 interface.
func (r *r2EndpointResolver) ResolveEndpoint(ctx context.Context, params s3.EndpointParameters) (smithyendpoints.Endpoint, error) {
	u, err := url.Parse(r.endpoint)
	if err != nil {
		return smithyendpoints.Endpoint{}, fmt.Errorf("storage: invalid S3 endpoint %q: %w", r.endpoint, err)
	}
	return smithyendpoints.Endpoint{URI: *u}, nil
}

// NewS3Client creates a new S3Client using the provided configuration.
// It configures a custom endpoint resolver for R2/S3-compatible providers,
// static credentials, and the specified region.
func NewS3Client(cfg *config.Config) (*S3Client, error) {
	if cfg.S3Endpoint == "" {
		return nil, fmt.Errorf("storage: S3_ENDPOINT is required")
	}
	if cfg.S3Bucket == "" {
		return nil, fmt.Errorf("storage: S3_BUCKET is required")
	}

	// Parse the endpoint to extract the host for SSRF validation.
	parsedEndpoint, err := url.Parse(cfg.S3Endpoint)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to parse S3_ENDPOINT %q: %w", cfg.S3Endpoint, err)
	}
	endpointHost := parsedEndpoint.Host
	if endpointHost == "" {
		return nil, fmt.Errorf("storage: S3_ENDPOINT %q has no host", cfg.S3Endpoint)
	}

	// Build AWS config with static credentials and custom endpoint resolver.
	awsCfg := aws.Config{
		Region: cfg.S3Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.S3AccessKeyID,
			cfg.S3SecretAccessKey,
			"", // session token — not used for R2/static credentials
		),
	}

	// Create the S3 client with the custom endpoint resolver.
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.EndpointResolverV2 = &r2EndpointResolver{endpoint: cfg.S3Endpoint}
		// R2 uses path-style addressing; virtual-hosted-style is the default for AWS.
		o.UsePathStyle = true
	})

	presignClient := s3.NewPresignClient(s3Client)

	return &S3Client{
		client:       s3Client,
		presign:      presignClient,
		bucket:       cfg.S3Bucket,
		endpointHost: endpointHost,
	}, nil
}

// HealthCheck verifies connectivity to the S3/R2 bucket by issuing a HeadBucket
// request. Returns an error if the bucket is unreachable or inaccessible.
func (c *S3Client) HealthCheck(ctx context.Context) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.bucket),
	})
	if err != nil {
		return fmt.Errorf("storage: health check failed for bucket %q: %w", c.bucket, err)
	}
	return nil
}

// GeneratePresignedUploadURL generates a presigned PUT URL for uploading an
// object to S3/R2. The URL includes the x-amz-meta-expected-size header with
// the declared file size.
//
// After generating the URL, the host is validated against the configured
// S3 endpoint to prevent SSRF attacks.
//
// TTL should be 15 minutes (900 seconds) per the design spec.
func (c *S3Client) GeneratePresignedUploadURL(
	ctx context.Context,
	objectKey string,
	contentType string,
	sizeBytes int64,
	ttl time.Duration,
) (string, error) {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(objectKey),
		ContentType: aws.String(contentType),
		Metadata: map[string]string{
			"expected-size": fmt.Sprintf("%d", sizeBytes),
		},
	}

	presignedReq, err := c.presign.PresignPutObject(ctx, input,
		s3.WithPresignExpires(ttl),
	)
	if err != nil {
		return "", fmt.Errorf("storage: failed to generate presigned upload URL for %q: %w", objectKey, err)
	}

	if err := c.validatePresignedURLHost(presignedReq.URL, c.endpointHost); err != nil {
		return "", err
	}

	return presignedReq.URL, nil
}

// GeneratePresignedDownloadURL generates a presigned GET URL for downloading an
// object from S3/R2. The URL includes response-content-disposition and
// response-content-type parameters to force browser download and prevent MIME
// sniffing / reflected XSS.
//
// The filename is embedded in the Content-Disposition header as:
//
//	attachment; filename="{sanitized_filename}"
//
// After generating the URL, the host is validated against the configured
// S3 endpoint to prevent SSRF attacks.
func (c *S3Client) GeneratePresignedDownloadURL(
	ctx context.Context,
	objectKey string,
	filename string,
	contentType string,
	ttl time.Duration,
) (string, error) {
	// Sanitize the filename for use in the Content-Disposition header:
	// strip double-quotes and backslashes to prevent header injection.
	safeFilename := sanitizeContentDispositionFilename(filename)
	contentDisposition := fmt.Sprintf(`attachment; filename="%s"`, safeFilename)

	input := &s3.GetObjectInput{
		Bucket:                     aws.String(c.bucket),
		Key:                        aws.String(objectKey),
		ResponseContentDisposition: aws.String(contentDisposition),
		ResponseContentType:        aws.String(contentType),
	}

	presignedReq, err := c.presign.PresignGetObject(ctx, input,
		s3.WithPresignExpires(ttl),
	)
	if err != nil {
		return "", fmt.Errorf("storage: failed to generate presigned download URL for %q: %w", objectKey, err)
	}

	if err := c.validatePresignedURLHost(presignedReq.URL, c.endpointHost); err != nil {
		return "", err
	}

	return presignedReq.URL, nil
}

// HeadObjectWithRetry calls HeadObject with up to maxAttempts retries using
// a fixed backoff schedule: 0ms, 100ms, 300ms, 1000ms.
//
// This is used after a presigned upload to verify the object exists in S3/R2
// before activating the token (eventual consistency window).
//
// If maxAttempts is <= 0, it defaults to 4.
func (c *S3Client) HeadObjectWithRetry(
	ctx context.Context,
	objectKey string,
	maxAttempts int,
) (*s3.HeadObjectOutput, error) {
	if maxAttempts <= 0 {
		maxAttempts = 4
	}

	// Backoff delays for each attempt index (0-indexed).
	// Attempt 0: no delay, Attempt 1: 100ms, Attempt 2: 300ms, Attempt 3: 1000ms.
	delays := []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond, 1000 * time.Millisecond}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Apply delay before each attempt (0ms for the first attempt).
		delay := time.Duration(0)
		if attempt < len(delays) {
			delay = delays[attempt]
		} else {
			// For attempts beyond the defined schedule, use the last delay.
			delay = delays[len(delays)-1]
		}

		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("storage: HeadObject context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(delay):
			}
		}

		out, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(c.bucket),
			Key:    aws.String(objectKey),
		})
		if err == nil {
			return out, nil
		}

		lastErr = err

		// Check if context is done before retrying.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("storage: HeadObject context cancelled: %w", ctx.Err())
		}
	}

	return nil, fmt.Errorf("storage: HeadObject failed after %d attempts for %q: %w", maxAttempts, objectKey, lastErr)
}

// DeleteObject deletes an object from S3/R2. A 404 (NoSuchKey) response is
// treated as success to make the operation idempotent — safe to call even if
// the object has already been deleted.
func (c *S3Client) DeleteObject(ctx context.Context, objectKey string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(objectKey),
	})
	if err == nil {
		return nil
	}

	// Treat NoSuchKey as success (idempotent delete).
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return nil
	}

	// Also handle the generic 404 that some S3-compatible providers return
	// instead of the typed NoSuchKey error.
	var apiErr interface{ HTTPStatusCode() int }
	if errors.As(err, &apiErr) && apiErr.HTTPStatusCode() == 404 {
		return nil
	}

	return fmt.Errorf("storage: failed to delete object %q: %w", objectKey, err)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// validatePresignedURLHost parses rawURL and verifies that its host matches
// expectedHost. Returns ErrSSRFEndpointMismatch if the hosts differ.
//
// This prevents SSRF attacks where a misconfigured or tampered S3_ENDPOINT
// could cause the application to generate presigned URLs pointing to an
// attacker-controlled server.
func (c *S3Client) validatePresignedURLHost(rawURL, expectedHost string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("storage: failed to parse presigned URL: %w", err)
	}

	presignedHost := parsed.Host

	// For path-style URLs the presigned host is the endpoint host directly.
	// For virtual-hosted-style URLs the presigned host is "{bucket}.{endpoint-host}".
	// We accept both: exact match OR the presigned host ends with ".{expectedHost}".
	if presignedHost != expectedHost && !strings.HasSuffix(presignedHost, "."+expectedHost) {
		return ErrSSRFEndpointMismatch
	}

	return nil
}

// sanitizeContentDispositionFilename strips characters that could break the
// Content-Disposition header value. Specifically, it removes double-quotes and
// backslashes which are the only characters that need escaping inside a
// quoted-string per RFC 6266.
func sanitizeContentDispositionFilename(filename string) string {
	// Remove double-quotes and backslashes to prevent header injection.
	s := strings.ReplaceAll(filename, `"`, "")
	s = strings.ReplaceAll(s, `\`, "")
	return s
}
