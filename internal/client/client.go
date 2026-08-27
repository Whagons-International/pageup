package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	now        func() time.Time
	userAgent  string
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
		endpoint:   endpoint,
		privateKey: privateKey,
		httpClient: &http.Client{Timeout: 45 * time.Second},
		now:        time.Now,
		userAgent:  "pageup/" + version,
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
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nonce, decodeAPIError(response)
	}
	if output != nil {
		if err := decodeJSON(response.Body, output); err != nil {
			return nonce, err
		}
	}
	return nonce, nil
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
