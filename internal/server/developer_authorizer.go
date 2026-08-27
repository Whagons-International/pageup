package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var errDeveloperAccessRequired = errors.New("developer access required")

type DeveloperIdentity struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

type DeveloperAuthorizer interface {
	Authorize(context.Context, string) (DeveloperIdentity, error)
}

type whagonsDeveloperAuthorizer struct {
	url       string
	projectID string
	client    *http.Client
}

func NewWhagonsDeveloperAuthorizer(url, projectID string) DeveloperAuthorizer {
	return &whagonsDeveloperAuthorizer{
		url:       strings.TrimSpace(url),
		projectID: strings.TrimSpace(projectID),
		client:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (authorizer *whagonsDeveloperAuthorizer) Authorize(ctx context.Context, idToken string) (DeveloperIdentity, error) {
	if authorizer == nil || authorizer.url == "" || authorizer.projectID == "" {
		return DeveloperIdentity{}, errors.New("Whagons developer authorization is not configured")
	}
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return DeveloperIdentity{}, errDeveloperAccessRequired
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authorizer.url, bytes.NewReader(nil))
	if err != nil {
		return DeveloperIdentity{}, err
	}
	request.Header.Set("Authorization", "Bearer "+idToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Gonvex-Project-Id", authorizer.projectID)
	response, err := authorizer.client.Do(request)
	if err != nil {
		return DeveloperIdentity{}, fmt.Errorf("verify Whagons developer access: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return DeveloperIdentity{}, fmt.Errorf("read Whagons developer response: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return DeveloperIdentity{}, errDeveloperAccessRequired
	}
	if response.StatusCode != http.StatusOK {
		return DeveloperIdentity{}, fmt.Errorf("Whagons developer authorization returned %d", response.StatusCode)
	}
	var result struct {
		Authorized bool   `json:"authorized"`
		UserID     string `json:"userId"`
		Email      string `json:"email"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return DeveloperIdentity{}, fmt.Errorf("decode Whagons developer response: %w", err)
	}
	result.UserID = strings.TrimSpace(result.UserID)
	result.Email = strings.ToLower(strings.TrimSpace(result.Email))
	if !result.Authorized || result.UserID == "" || result.Email == "" {
		return DeveloperIdentity{}, errDeveloperAccessRequired
	}
	return DeveloperIdentity{UserID: result.UserID, Email: result.Email}, nil
}
