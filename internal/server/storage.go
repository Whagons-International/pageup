package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

const maxStoredObjectBytes = 8 << 20

type storedObject struct {
	Body         []byte
	LastModified time.Time
}

type objectStore interface {
	Get(string) (storedObject, error)
	Put(string, []byte, bool) (bool, error)
	Delete(string) error
	// PutStream and OpenStream move hosted files without buffering them in
	// memory. OpenStream receives the size recorded in file metadata.
	PutStream(context.Context, string, io.ReadSeeker, int64, string) error
	OpenStream(context.Context, string, int64) (io.ReadSeekCloser, error)
}

type filesystemObjectStore struct {
	root string
}

func newFilesystemObjectStore(root string) (*filesystemObjectStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("storage directory cannot be empty")
	}
	if err := os.MkdirAll(filepath.Join(root, "pages"), 0o700); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}
	return &filesystemObjectStore{root: root}, nil
}

func (store *filesystemObjectStore) path(key string) string {
	return filepath.Join(store.root, filepath.FromSlash(key))
}

func (store *filesystemObjectStore) Get(key string) (storedObject, error) {
	path := store.path(key)
	body, err := os.ReadFile(path)
	if err != nil {
		return storedObject{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return storedObject{}, err
	}
	return storedObject{Body: body, LastModified: info.ModTime()}, nil
}

func (store *filesystemObjectStore) Put(key string, body []byte, createOnly bool) (bool, error) {
	path := store.path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if createOnly {
		return writeImmutable(path, body)
	}
	if err := writeAtomicFile(path, body, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func (store *filesystemObjectStore) Delete(key string) error {
	err := os.Remove(store.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (store *filesystemObjectStore) PutStream(_ context.Context, key string, body io.ReadSeeker, _ int64, _ string) error {
	path := store.path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeAtomicStream(path, body, 0o600)
}

func (store *filesystemObjectStore) OpenStream(_ context.Context, key string, _ int64) (io.ReadSeekCloser, error) {
	return os.Open(store.path(key))
}

type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string
}

type s3ObjectStore struct {
	client *s3.Client
	bucket string
	prefix string
}

func newS3ObjectStore(config S3Config) (*s3ObjectStore, error) {
	config.Endpoint = strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	config.Region = strings.TrimSpace(config.Region)
	config.Bucket = strings.TrimSpace(config.Bucket)
	config.AccessKeyID = strings.TrimSpace(config.AccessKeyID)
	config.SecretAccessKey = strings.TrimSpace(config.SecretAccessKey)
	config.Prefix = strings.Trim(strings.TrimSpace(config.Prefix), "/")
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("PAGEUP_S3_ENDPOINT must be an HTTP origin")
	}
	if config.Region == "" {
		config.Region = "us-east-1"
	}
	if config.Bucket == "" || config.AccessKeyID == "" || config.SecretAccessKey == "" {
		return nil, errors.New("PAGEUP_S3_BUCKET, PAGEUP_S3_ACCESS_KEY_ID, and PAGEUP_S3_SECRET_ACCESS_KEY are required")
	}
	loaded, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(config.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("configure S3 storage: %w", err)
	}
	client := s3.NewFromConfig(loaded, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = true
	})
	store := &s3ObjectStore{client: client, bucket: config.Bucket, prefix: config.Prefix}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(config.Bucket)}); err != nil {
		return nil, fmt.Errorf("access S3 bucket %q: %w", config.Bucket, err)
	}
	return store, nil
}

func (store *s3ObjectStore) objectKey(key string) string {
	if store.prefix == "" {
		return key
	}
	return store.prefix + "/" + key
}

func (store *s3ObjectStore) Get(key string) (storedObject, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := store.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bucket),
		Key:    aws.String(store.objectKey(key)),
	})
	if err != nil {
		if s3NotFound(err) {
			return storedObject{}, os.ErrNotExist
		}
		return storedObject{}, err
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, maxStoredObjectBytes+1))
	if err != nil {
		return storedObject{}, err
	}
	if len(body) > maxStoredObjectBytes {
		return storedObject{}, errors.New("stored object exceeds Pageup's read limit")
	}
	modified := time.Now().UTC()
	if result.LastModified != nil {
		modified = result.LastModified.UTC()
	}
	return storedObject{Body: body, LastModified: modified}, nil
}

func (store *s3ObjectStore) Put(key string, body []byte, createOnly bool) (bool, error) {
	if createOnly {
		existing, err := store.Get(key)
		if err == nil {
			if bytes.Equal(existing.Body, body) {
				return false, nil
			}
			return false, errContentConflict
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(store.bucket),
		Key:           aws.String(store.objectKey(key)),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (store *s3ObjectStore) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(store.bucket),
		Key:    aws.String(store.objectKey(key)),
	})
	return err
}

func (store *s3ObjectStore) PutStream(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	_, err := store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(store.bucket),
		Key:           aws.String(store.objectKey(key)),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	var apiError smithy.APIError
	if errors.As(err, &apiError) && apiError.ErrorCode() == "EntityTooLarge" {
		return fmt.Errorf("%w: %v", errObjectTooLarge, err)
	}
	return err
}

// OpenStream starts the download immediately so a missing object is reported
// before any response headers are written.
func (store *s3ObjectStore) OpenStream(ctx context.Context, key string, size int64) (io.ReadSeekCloser, error) {
	reader := &s3StreamReader{ctx: ctx, store: store, key: key, size: size}
	if err := reader.open(); err != nil {
		return nil, err
	}
	return reader, nil
}

// s3StreamReader adapts GetObject to io.ReadSeeker for http.ServeContent. A
// seek only records the position; the next read reopens the object with a
// Range request when the position no longer matches the open body.
type s3StreamReader struct {
	ctx        context.Context
	store      *s3ObjectStore
	key        string
	size       int64
	offset     int64
	body       io.ReadCloser
	bodyOffset int64
}

func (reader *s3StreamReader) open() error {
	input := &s3.GetObjectInput{
		Bucket: aws.String(reader.store.bucket),
		Key:    aws.String(reader.store.objectKey(reader.key)),
	}
	if reader.offset > 0 {
		input.Range = aws.String(fmt.Sprintf("bytes=%d-", reader.offset))
	}
	result, err := reader.store.client.GetObject(reader.ctx, input)
	if err != nil {
		if s3NotFound(err) {
			return os.ErrNotExist
		}
		return err
	}
	reader.body = result.Body
	reader.bodyOffset = reader.offset
	return nil
}

func (reader *s3StreamReader) Read(buffer []byte) (int, error) {
	if reader.offset >= reader.size {
		return 0, io.EOF
	}
	if reader.body != nil && reader.bodyOffset != reader.offset {
		reader.body.Close()
		reader.body = nil
	}
	if reader.body == nil {
		if err := reader.open(); err != nil {
			return 0, err
		}
	}
	count, err := reader.body.Read(buffer)
	reader.offset += int64(count)
	reader.bodyOffset = reader.offset
	if errors.Is(err, io.EOF) && reader.offset < reader.size {
		err = io.ErrUnexpectedEOF
	}
	return count, err
}

func (reader *s3StreamReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += reader.offset
	case io.SeekEnd:
		offset += reader.size
	default:
		return 0, errors.New("invalid seek whence")
	}
	if offset < 0 {
		return 0, errors.New("negative seek position")
	}
	reader.offset = offset
	return offset, nil
}

func (reader *s3StreamReader) Close() error {
	if reader.body == nil {
		return nil
	}
	err := reader.body.Close()
	reader.body = nil
	return err
}

func s3NotFound(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	switch apiError.ErrorCode() {
	case "NoSuchKey", "NotFound", "404":
		return true
	default:
		return false
	}
}
