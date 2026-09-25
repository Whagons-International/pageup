package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/protocol"
	"github.com/desarso/pageup/internal/sitebundle"
)

type Client struct {
	endpoint   *url.URL
	privateKey ed25519.PrivateKey
	httpClient *http.Client
	// transferClient has no overall timeout because file transfers can run
	// long; callers bound them with a context instead.
	transferClient *http.Client
	now            func() time.Time
	userAgent      string
}

type APIError struct {
	StatusCode int
	Message    string
}

func (err *APIError) Error() string {
	return fmt.Sprintf("server returned %d: %s", err.StatusCode, err.Message)
}

func New(config Config, version string) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	endpoint, _ := url.Parse(strings.TrimRight(config.Endpoint, "/"))
	privateKey, _ := config.Private()
	return &Client{
		endpoint:       endpoint,
		privateKey:     privateKey,
		httpClient:     &http.Client{Timeout: 45 * time.Second},
		transferClient: &http.Client{},
		now:            time.Now,
		userAgent:      "pageup/" + version,
	}, nil
}

func (client *Client) Upload(ctx context.Context, html []byte) (api.UploadResponse, error) {
	var result api.UploadResponse
	_, err := client.doSigned(ctx, http.MethodPost, "/api/pages", html, "text/html; charset=utf-8", &result)
	return result, err
}

func (client *Client) UploadSite(ctx context.Context, archive []byte) (api.UploadResponse, error) {
	var result api.UploadResponse
	_, err := client.doSigned(ctx, http.MethodPost, "/api/pages", archive, sitebundle.MediaType, &result)
	return result, err
}

func (client *Client) Update(ctx context.Context, id string, html []byte) (api.UploadResponse, error) {
	if !protocol.IsUUIDv7(id) {
		return api.UploadResponse{}, errors.New("page id must be a UUIDv7")
	}
	var result api.UploadResponse
	_, err := client.doSigned(ctx, http.MethodPut, "/api/pages/"+url.PathEscape(id), html, "text/html; charset=utf-8", &result)
	return result, err
}

func (client *Client) UpdateSite(ctx context.Context, id string, archive []byte) (api.UploadResponse, error) {
	if !protocol.IsUUIDv7(id) {
		return api.UploadResponse{}, errors.New("page id must be a UUIDv7")
	}
	var result api.UploadResponse
	_, err := client.doSigned(ctx, http.MethodPut, "/api/pages/"+url.PathEscape(id), archive, sitebundle.MediaType, &result)
	return result, err
}

// UploadFile streams content to a new hosted file published under name.
func (client *Client) UploadFile(ctx context.Context, name string, content io.ReadSeeker) (api.FileResponse, error) {
	var result api.FileResponse
	err := client.doSignedStream(ctx, http.MethodPost, "/api/files/"+url.PathEscape(name), content, &result)
	return result, err
}

// UpdateFile replaces a hosted file's content at the same URL. An empty name
// keeps the current file name.
func (client *Client) UpdateFile(ctx context.Context, id, name string, content io.ReadSeeker) (api.FileResponse, error) {
	if !protocol.IsUUIDv7(id) {
		return api.FileResponse{}, errors.New("file id must be a UUIDv7")
	}
	path := "/api/files/" + url.PathEscape(id)
	if name != "" {
		path += "/" + url.PathEscape(name)
	}
	var result api.FileResponse
	err := client.doSignedStream(ctx, http.MethodPut, path, content, &result)
	return result, err
}

func (client *Client) DeleteFile(ctx context.Context, id string) (api.FileResponse, error) {
	if !protocol.IsUUIDv7(id) {
		return api.FileResponse{}, errors.New("file id must be a UUIDv7")
	}
	var result api.FileResponse
	_, err := client.doSigned(ctx, http.MethodDelete, "/api/files/"+url.PathEscape(id), nil, "", &result)
	return result, err
}

func (client *Client) AddKey(ctx context.Context, input api.AddKeyRequest) (api.Key, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return api.Key{}, err
	}
	var result api.Key
	_, err = client.doSigned(ctx, http.MethodPost, "/api/keys", body, "application/json", &result)
	return result, err
}

func (client *Client) ListKeys(ctx context.Context) ([]api.Key, error) {
	var result api.KeyListResponse
	_, err := client.doSigned(ctx, http.MethodGet, "/api/keys", nil, "", &result)
	return result.Keys, err
}

func (client *Client) RevokeKey(ctx context.Context, id string) (api.Key, error) {
	var result api.Key
	_, err := client.doSigned(ctx, http.MethodDelete, "/api/keys/"+url.PathEscape(id), nil, "", &result)
	return result, err
}

func (client *Client) WhoAmI(ctx context.Context) (api.Key, error) {
	var result api.WhoAmIResponse
	_, err := client.doSigned(ctx, http.MethodGet, "/api/whoami", nil, "", &result)
	return result.Key, err
}

func (client *Client) Health(ctx context.Context) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint.String()+"/health", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", client.userAgent)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response)
	}
	var result map[string]string
	if err := decodeJSON(response.Body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (client *Client) StartDeviceAuth(ctx context.Context, name, publicKey string) (api.DeviceAuthStartResponse, error) {
	body, err := json.Marshal(api.DeviceAuthStartRequest{Name: name, PublicKey: publicKey})
	if err != nil {
		return api.DeviceAuthStartResponse{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String()+"/api/auth/device/start", bytes.NewReader(body))
	if err != nil {
		return api.DeviceAuthStartResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.userAgent)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return api.DeviceAuthStartResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return api.DeviceAuthStartResponse{}, decodeAPIError(response)
	}
	var result api.DeviceAuthStartResponse
	if err := decodeJSON(response.Body, &result); err != nil {
		return api.DeviceAuthStartResponse{}, err
	}
	return result, nil
}

func (client *Client) DeviceAuthStatus(ctx context.Context, id string) (api.DeviceAuthStatusResponse, error) {
	if !protocol.IsUUIDv7(id) {
		return api.DeviceAuthStatusResponse{}, errors.New("device authorization id must be a UUIDv7")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint.String()+"/api/auth/device/"+url.PathEscape(id), nil)
	if err != nil {
		return api.DeviceAuthStatusResponse{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.userAgent)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return api.DeviceAuthStatusResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return api.DeviceAuthStatusResponse{}, decodeAPIError(response)
	}
	var result api.DeviceAuthStatusResponse
	if err := decodeJSON(response.Body, &result); err != nil {
		return api.DeviceAuthStatusResponse{}, err
	}
	return result, nil
}

func (client *Client) doSigned(ctx context.Context, method, path string, body []byte, contentType string, output any) (string, error) {
	nonce, err := protocol.NewUUIDv7(client.now())
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint.String()+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.userAgent)
	protocol.SignRequest(request, client.privateKey, nonce, body, client.now())
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nonce, err
	}
	return nonce, decodeResponse(response, output)
}

// doSignedStream hashes content, then streams it with the hash in a signed
// header so neither side holds the whole body in memory.
func (client *Client) doSignedStream(ctx context.Context, method, path string, content io.ReadSeeker, output any) error {
	hash := sha256.New()
	size, err := io.Copy(hash, content)
	if err != nil {
		return err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return err
	}
	nonce, err := protocol.NewUUIDv7(client.now())
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint.String()+path, nil)
	if err != nil {
		return err
	}
	if size > 0 {
		request.Body = io.NopCloser(content)
		request.GetBody = func() (io.ReadCloser, error) {
			if _, err := content.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return io.NopCloser(content), nil
		}
		request.ContentLength = size
		// Wait briefly for the server to accept the signature before sending
		// a large body it would reject.
		request.Header.Set("Expect", "100-continue")
	}
	bodyHash := hex.EncodeToString(hash.Sum(nil))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.userAgent)
	request.Header.Set(protocol.HeaderContentSHA256, bodyHash)
	protocol.SignRequestHash(request, client.privateKey, nonce, bodyHash, client.now())
	response, err := client.transferClient.Do(request)
	if err != nil {
		return err
	}
	return decodeResponse(response, output)
}

func decodeResponse(response *http.Response, output any) error {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	if output != nil {
		return decodeJSON(response.Body, output)
	}
	return nil
}

func decodeAPIError(response *http.Response) error {
	var result api.ErrorResponse
	if err := decodeJSON(response.Body, &result); err != nil || result.Error == "" {
		result.Error = http.StatusText(response.StatusCode)
	}
	return &APIError{StatusCode: response.StatusCode, Message: result.Error}
}

func decodeJSON(reader io.Reader, output any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 2<<20))
	if err := decoder.Decode(output); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("server returned an empty response")
		}
		return fmt.Errorf("decode server response: %w", err)
	}
	return nil
}
