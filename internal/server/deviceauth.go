package server

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/protocol"
)

const (
	deviceAuthPending  = "pending"
	deviceAuthApproved = "approved"
	deviceAuthDenied   = "denied"
	deviceAuthExpired  = "expired"
	deviceAuthLifetime = 10 * time.Minute
	maxDeviceAuthFlows = 500
)

type deviceAuthSession struct {
	ID        string
	Name      string
	PublicKey string
	KeyID     string
	Status    string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type deviceAuthStore struct {
	mu         sync.Mutex
	now        func() time.Time
	authorizer DeveloperAuthorizer
	sessions   map[string]deviceAuthSession
}

func newDeviceAuthStore(now func() time.Time, authorizer DeveloperAuthorizer) *deviceAuthStore {
	return &deviceAuthStore{now: now, authorizer: authorizer, sessions: make(map[string]deviceAuthSession)}
}

func (store *deviceAuthStore) create(name, publicKey string) (deviceAuthSession, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return deviceAuthSession{}, errors.New("device name must be between 1 and 80 characters")
	}
	decoded, err := protocol.DecodePublicKey(strings.TrimSpace(publicKey))
	if err != nil {
		return deviceAuthSession{}, errors.New("invalid public key")
	}
	now := store.now().UTC()
	id, err := protocol.NewUUIDv7(now)
	if err != nil {
		return deviceAuthSession{}, err
	}
	session := deviceAuthSession{
		ID:        id,
		Name:      name,
		PublicKey: protocol.EncodePublicKey(decoded),
		KeyID:     protocol.KeyID(decoded),
		Status:    deviceAuthPending,
		CreatedAt: now,
		ExpiresAt: now.Add(deviceAuthLifetime),
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupLocked(now)
	if len(store.sessions) >= maxDeviceAuthFlows {
		return deviceAuthSession{}, errors.New("too many pending device sign-ins; try again shortly")
	}
	store.sessions[id] = session
	return session, nil
}

func (store *deviceAuthStore) get(id string) (deviceAuthSession, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().UTC()
	store.cleanupLocked(now)
	session, ok := store.sessions[id]
	if !ok {
		return deviceAuthSession{}, false
	}
	if session.Status == deviceAuthPending && !now.Before(session.ExpiresAt) {
		session.Status = deviceAuthExpired
		store.sessions[id] = session
	}
	return session, true
}

func (store *deviceAuthStore) approve(ctx context.Context, id, token string, keys *KeyStore) (deviceAuthSession, error) {
	session, ok := store.get(id)
	if !ok {
		return deviceAuthSession{}, errors.New("device sign-in was not found")
	}
	if session.Status == deviceAuthApproved {
		return session, nil
	}
	if session.Status != deviceAuthPending {
		return deviceAuthSession{}, errors.New("device sign-in is no longer active")
	}
	if store.authorizer == nil {
		return deviceAuthSession{}, errors.New("Google sign-in is not configured")
	}
	identity, err := store.authorizer.Authorize(ctx, token)
	if err != nil {
		if errors.Is(err, errDeveloperAccessRequired) {
			store.setStatus(id, deviceAuthDenied, "")
		}
		return deviceAuthSession{}, err
	}
	publicKey, err := protocol.DecodePublicKey(session.PublicKey)
	if err != nil {
		return deviceAuthSession{}, err
	}
	if _, _, err := keys.Add(deviceKeyName(session.Name, identity.Email), publicKey, RoleUpload, store.now()); err != nil {
		return deviceAuthSession{}, err
	}
	return store.setStatus(id, deviceAuthApproved, identity.Email), nil
}

func deviceKeyName(name, email string) string {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	label := name + " (" + email + ")"
	for len(label) > 80 {
		runes := []rune(label)
		if len(runes) == 0 {
			return "Whagons developer device"
		}
		label = strings.TrimSpace(string(runes[:len(runes)-1]))
	}
	return label
}

func (store *deviceAuthStore) setStatus(id, status, email string) deviceAuthSession {
	store.mu.Lock()
	defer store.mu.Unlock()
	session := store.sessions[id]
	session.Status = status
	session.Email = email
	store.sessions[id] = session
	return session
}

func (store *deviceAuthStore) cleanupLocked(now time.Time) {
	for id, session := range store.sessions {
		if now.After(session.ExpiresAt.Add(10 * time.Minute)) {
			delete(store.sessions, id)
		}
	}
}

func (server *Server) handleDeviceAuthStart(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	body, ok := readBody(writer, request, 32<<10)
	if !ok {
		return
	}
	var input api.DeviceAuthStartRequest
	if err := json.Unmarshal(body, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	session, err := server.auth.create(input.Name, input.PublicKey)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, api.DeviceAuthStartResponse{
		ID:              session.ID,
		VerificationURL: server.publicURL(request) + "/auth/device/" + session.ID,
		ExpiresAt:       session.ExpiresAt,
		IntervalSeconds: 2,
	})
}

func (server *Server) handleDeviceAuth(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api/auth/device/")
	id, action, hasAction := strings.Cut(path, "/")
	if !protocol.IsUUIDv7(id) {
		http.NotFound(writer, request)
		return
	}
	if !hasAction && request.Method == http.MethodGet {
		session, ok := server.auth.get(id)
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writeJSON(writer, http.StatusOK, api.DeviceAuthStatusResponse{Status: session.Status, Email: session.Email})
		return
	}
	if action != "complete" || request.Method != http.MethodPost {
		http.NotFound(writer, request)
		return
	}
	body, ok := readBody(writer, request, 2<<20)
	if !ok {
		return
	}
	var input api.DeviceAuthCompleteRequest
	if err := json.Unmarshal(body, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	session, err := server.auth.approve(request.Context(), id, input.IDToken, server.keys)
	if errors.Is(err, errDeveloperAccessRequired) {
		writeError(writer, http.StatusForbidden, "this Google account does not have Whagons developer access")
		return
	}
	if err != nil {
		server.config.Logger.Error("authorize Pageup device", "error", err)
		writeError(writer, http.StatusBadGateway, "could not verify Whagons developer access")
		return
	}
	writeJSON(writer, http.StatusOK, api.DeviceAuthStatusResponse{Status: session.Status, Email: session.Email})
}

func (server *Server) handleDeviceAuthPage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/auth/device/")
	if !protocol.IsUUIDv7(id) {
		http.NotFound(writer, request)
		return
	}
	session, ok := server.auth.get(id)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline' https://www.gstatic.com; style-src 'unsafe-inline'; connect-src 'self' https://*.googleapis.com https://securetoken.googleapis.com https://identitytoolkit.googleapis.com; frame-src https://accounts.google.com https://*.firebaseapp.com; img-src data: https://*.googleusercontent.com; base-uri 'none'; form-action 'none'")
	if err := deviceAuthPageTemplate.Execute(writer, session); err != nil {
		server.config.Logger.Error("render device authorization page", "error", err)
	}
}

var deviceAuthPageTemplate = template.Must(template.New("device-auth").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0c0d0e">
<title>Authorize Pageup</title>
<style>
  :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0c0d0e; color: #ede7d9; }
  main { width: min(34rem, calc(100% - 3rem)); border: 1px solid #34322e; padding: clamp(1.5rem, 5vw, 3rem); background: #151616; }
  h1 { margin: 0 0 1rem; font-size: clamp(2rem, 8vw, 3.5rem); letter-spacing: -.06em; }
  p { color: #aaa59b; line-height: 1.65; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .7rem 1rem; margin: 1.5rem 0; }
  dt { color: #77736c; } dd { margin: 0; overflow-wrap: anywhere; }
  button { width: 100%; border: 0; padding: .9rem 1rem; background: #c9ff3d; color: #111; font: inherit; font-weight: 700; cursor: pointer; }
  button:disabled { opacity: .55; cursor: wait; }
  #status { min-height: 1.5rem; color: #f7a65a; }
</style>
<main data-flow-id="{{.ID}}">
  <h1>Authorize Pageup</h1>
  <p>Sign in with the Google account that has Whagons developer access. This authorizes one upload-only device key. Pageup does not keep your Google token.</p>
  <dl><dt>Device</dt><dd>{{.Name}}</dd><dt>Key</dt><dd>{{.KeyID}}</dd></dl>
  {{if eq .Status "pending"}}<button id="authorize">Continue with Google</button>{{else}}<button disabled>This request is {{.Status}}</button>{{end}}
  <p id="status" role="status"></p>
</main>
<script type="module">
  import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js';
  import { getAuth, GoogleAuthProvider, signInWithPopup } from 'https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js';
  const config = { apiKey: 'AIzaSyAD1bLLRlRUoS2rEg3ZKqGQ3bE1chfySSY', authDomain: 'whagons-5.firebaseapp.com', projectId: 'whagons-5', appId: '1:578623964983:web:6d30a61ae7997530dbfcb2' };
  const button = document.querySelector('#authorize');
  const status = document.querySelector('#status');
  const flowId = document.querySelector('main').dataset.flowId;
  if (button) button.addEventListener('click', async () => {
    button.disabled = true;
    status.textContent = 'Waiting for Google sign-in...';
    try {
      const result = await signInWithPopup(getAuth(initializeApp(config)), new GoogleAuthProvider());
      const response = await fetch('/api/auth/device/' + encodeURIComponent(flowId) + '/complete', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id_token: await result.user.getIdToken(true) })
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || 'Authorization failed');
      status.textContent = 'Authorized as ' + body.email + '. You can close this tab.';
      button.textContent = 'Authorized';
    } catch (error) {
      status.textContent = error?.message || 'Authorization failed';
      button.disabled = false;
    }
  });
</script>
</html>`))
