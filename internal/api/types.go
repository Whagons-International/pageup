package api

import "time"

type ErrorResponse struct {
	Error string `json:"error"`
}

type DeviceAuthStartRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type DeviceAuthStartResponse struct {
	ID              string    `json:"id"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	IntervalSeconds int       `json:"interval_seconds"`
}

type DeviceAuthStatusResponse struct {
	Status string `json:"status"`
	Email  string `json:"email,omitempty"`
}

type DeviceAuthCompleteRequest struct {
	IDToken string `json:"id_token"`
}

type UploadResponse struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Created  bool   `json:"created"`
	Updated  bool   `json:"updated"`
	Revision uint64 `json:"revision"`
}

type Key struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key,omitempty"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AddKeyRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Role      string `json:"role"`
}

type KeyListResponse struct {
	Keys []Key `json:"keys"`
}

type WhoAmIResponse struct {
	Key Key `json:"key"`
}
