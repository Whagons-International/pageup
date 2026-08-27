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
