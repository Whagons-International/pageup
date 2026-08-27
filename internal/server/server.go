package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/protocol"
	"github.com/desarso/pageup/internal/sitebundle"
)

const (
	defaultMaxPageBytes    int64 = 5 << 20
	maxSiteArchiveOverhead       = 1 << 20
)

type Config struct {
	DataDir       string
	PublicURL     string
	DownloadsDir  string
	BootstrapKeys string
	MaxPageBytes  int64
	Version       string
	Logger        *slog.Logger
	Now           func() time.Time
	Authorizer    DeveloperAuthorizer
	S3            S3Config
	storage       objectStore
}

type Server struct {
	config Config
	keys   *KeyStore
	auth   *deviceAuthStore
	store  objectStore
	pages  sync.Mutex
	nonces struct {
		sync.Mutex
		used map[string]time.Time
	}
}

func New(config Config) (*Server, error) {
	if config.DataDir == "" {
		config.DataDir = "./data"
	}
	if config.MaxPageBytes <= 0 {
		config.MaxPageBytes = defaultMaxPageBytes
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.PublicURL = strings.TrimRight(config.PublicURL, "/")
	if config.PublicURL != "" {
		parsed, err := url.Parse(config.PublicURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" {
			return nil, errors.New("PAGEUP_PUBLIC_URL must be an origin such as https://pages.example.com")
		}
	}
	store := config.storage
	if store == nil {
		var err error
		if strings.TrimSpace(config.S3.Endpoint) != "" {
			store, err = newS3ObjectStore(config.S3)
		} else {
			store, err = newFilesystemObjectStore(config.DataDir)
		}
		if err != nil {
			return nil, err
		}
	}
	keys, err := newKeyStore(store, "keys.json", config.BootstrapKeys, config.Now())
	if err != nil {
		return nil, err
	}
	server := &Server{config: config, keys: keys, store: store}
	server.auth = newDeviceAuthStore(config.Now, config.Authorizer)
	server.nonces.used = make(map[string]time.Time)
	return server, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/robots.txt", server.handleRobots)
	mux.HandleFunc("/favicon.svg", server.handleFavicon)
	mux.HandleFunc("/favicon.ico", server.handleFavicon)
	mux.HandleFunc("/install.sh", server.handleInstallShell)
	mux.HandleFunc("/install.ps1", server.handleInstallPowerShell)
	mux.HandleFunc("/downloads/", server.handleDownload)
	mux.HandleFunc("/auth/device/", server.handleDeviceAuthPage)
	mux.HandleFunc("/api/auth/device/start", server.handleDeviceAuthStart)
	mux.HandleFunc("/api/auth/device/", server.handleDeviceAuth)
	mux.HandleFunc("/api/pages", server.handleUpload)
	mux.HandleFunc("/api/pages/", server.handleUpdate)
	mux.HandleFunc("/api/keys", server.handleKeys)
	mux.HandleFunc("/api/keys/", server.handleKey)
	mux.HandleFunc("/api/whoami", server.handleWhoAmI)
	mux.HandleFunc("/", server.handlePage)
	return server.securityHeaders(server.accessLog(mux))
}

func (server *Server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "version": server.config.Version})
}

func (server *Server) handleRobots(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func (server *Server) handleFavicon(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	writer.Header().Set("Content-Type", "image/svg+xml")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	writer.Header().Set("Content-Length", strconv.Itoa(len(faviconSVG)))
	if request.Method == http.MethodHead {
		writer.WriteHeader(http.StatusOK)
		return
	}
	io.WriteString(writer, faviconSVG)
}

func (server *Server) handleUpload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	kind, ok := pageKindFromContentType(request.Header.Get("Content-Type"))
	if !ok {
		writeError(writer, http.StatusUnsupportedMediaType, "Content-Type must be text/html or "+sitebundle.MediaType)
		return
	}
	maxBodyBytes := server.config.MaxPageBytes
	if kind == pageKindSite {
		maxBodyBytes += maxSiteArchiveOverhead
	}
	body, ok := readBody(writer, request, maxBodyBytes)
	if !ok {
		return
	}
	key, nonce, ok := server.authorize(writer, request, body, false)
	if !ok {
		return
	}
	if !protocol.IsUUIDv7(nonce) {
		writeError(writer, http.StatusUnauthorized, "authentication failed")
		return
	}
	if len(body) == 0 {
		writeError(writer, http.StatusBadRequest, "HTML upload cannot be empty")
		return
	}
	if kind == pageKindSite {
		if _, err := sitebundle.Parse(body, server.config.MaxPageBytes); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid HTML site: "+err.Error())
			return
		}
	}
	created, metadata, err := server.createPage(nonce, key, kind, body)
	if err != nil {
		if errors.Is(err, errContentConflict) {
			writeError(writer, http.StatusConflict, "page id already exists with different content")
			return
		}
		server.config.Logger.Error("write page", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not store page")
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(writer, status, api.UploadResponse{
		ID:       nonce,
		URL:      server.pageURL(request, nonce, kind),
		Created:  created,
		Revision: metadata.Revision,
	})
}

func (server *Server) handleUpdate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPut {
		methodNotAllowed(writer, http.MethodPut)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/api/pages/")
	if !protocol.IsUUIDv7(id) {
		http.NotFound(writer, request)
		return
	}
	kind, ok := pageKindFromContentType(request.Header.Get("Content-Type"))
	if !ok {
		writeError(writer, http.StatusUnsupportedMediaType, "Content-Type must be text/html or "+sitebundle.MediaType)
		return
	}
	maxBodyBytes := server.config.MaxPageBytes
	if kind == pageKindSite {
		maxBodyBytes += maxSiteArchiveOverhead
	}
	body, ok := readBody(writer, request, maxBodyBytes)
	if !ok {
		return
	}
	key, _, ok := server.authorize(writer, request, body, false)
	if !ok {
		return
	}
	if len(body) == 0 {
		writeError(writer, http.StatusBadRequest, "HTML upload cannot be empty")
		return
	}
	if kind == pageKindSite {
		if _, err := sitebundle.Parse(body, server.config.MaxPageBytes); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid HTML site: "+err.Error())
			return
		}
	}
	updated, metadata, err := server.updatePage(id, key, kind, body)
	if errors.Is(err, os.ErrNotExist) {
		writeError(writer, http.StatusNotFound, "page not found")
		return
	}
	if errors.Is(err, errPageForbidden) {
		writeError(writer, http.StatusForbidden, "this key cannot update that page")
		return
	}
	if err != nil {
		server.config.Logger.Error("update page", "page_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not update page")
		return
	}
	writeJSON(writer, http.StatusOK, api.UploadResponse{
		ID:       id,
		URL:      server.pageURL(request, id, kind),
		Updated:  updated,
		Revision: metadata.Revision,
	})
}

func (server *Server) handleWhoAmI(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	key, _, ok := server.authorize(writer, request, nil, false)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, api.WhoAmIResponse{Key: key})
}

func (server *Server) handleKeys(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		_, _, ok := server.authorize(writer, request, nil, true)
		if !ok {
			return
		}
		writeJSON(writer, http.StatusOK, api.KeyListResponse{Keys: server.keys.List()})
	case http.MethodPost:
		body, ok := readBody(writer, request, 64<<10)
		if !ok {
			return
		}
		_, _, ok = server.authorize(writer, request, body, true)
		if !ok {
			return
		}
		var input api.AddKeyRequest
		if err := json.Unmarshal(body, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid JSON request")
			return
		}
		publicKey, err := protocol.DecodePublicKey(input.PublicKey)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid public key")
			return
		}
		if input.Role == "" {
			input.Role = RoleUpload
		}
		key, created, err := server.keys.Add(input.Name, publicKey, input.Role, server.config.Now())
		if err != nil {
			writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		status := http.StatusCreated
		if !created {
			status = http.StatusOK
		}
		writeJSON(writer, status, key)
	default:
		writer.Header().Set("Allow", "GET, POST")
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (server *Server) handleKey(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodDelete)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/api/keys/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(writer, request)
		return
	}
	_, _, ok := server.authorize(writer, request, nil, true)
	if !ok {
		return
	}
	key, err := server.keys.Remove(id)
	if errors.Is(err, os.ErrNotExist) {
		writeError(writer, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, key)
}

func (server *Server) handlePage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if request.URL.Path == "/" {
		server.handleLanding(writer)
		return
	}
	pagePath := strings.TrimPrefix(request.URL.Path, "/")
	id, subpath, hasSubpath := strings.Cut(pagePath, "/")
	if !protocol.IsUUIDv7(id) {
		http.NotFound(writer, request)
		return
	}
	server.pages.Lock()
	kind, _, stored, err := server.readPageContent(id)
	server.pages.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not read page")
		return
	}
	if kind == pageKindHTML {
		if hasSubpath {
			http.NotFound(writer, request)
			return
		}
		serveHTML(writer, request, id+".html", stored.LastModified, stored.Body)
		return
	}
	if !hasSubpath {
		redirectWithSlash(writer, request)
		return
	}
	site, err := sitebundle.Parse(stored.Body, server.config.MaxPageBytes)
	if err != nil {
		server.config.Logger.Error("read HTML site", "page_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not read page")
		return
	}
	requested := subpath
	if requested == "" {
		requested = "index.html"
	} else if strings.HasSuffix(requested, "/") {
		requested += "index.html"
	}
	contents, exists := site.Files[requested]
	if !exists && subpath != "" && !strings.HasSuffix(subpath, "/") {
		if _, hasIndex := site.Files[subpath+"/index.html"]; hasIndex {
			redirectWithSlash(writer, request)
			return
		}
	}
	if !exists {
		http.NotFound(writer, request)
		return
	}
	serveHTML(writer, request, requested, stored.LastModified, contents)
}

func pageKindFromContentType(value string) (pageKind, bool) {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", false
	}
	switch mediaType {
	case "text/html", "application/xhtml+xml":
		return pageKindHTML, true
	case sitebundle.MediaType:
		return pageKindSite, true
	default:
		return "", false
	}
}

func (server *Server) pageURL(request *http.Request, id string, kind pageKind) string {
	result := server.publicURL(request) + "/" + id
	if kind == pageKindSite {
		result += "/"
	}
	return result
}

func redirectWithSlash(writer http.ResponseWriter, request *http.Request) {
	location := request.URL.EscapedPath() + "/"
	if request.URL.RawQuery != "" {
		location += "?" + request.URL.RawQuery
	}
	http.Redirect(writer, request, location, http.StatusPermanentRedirect)
}

func serveHTML(writer http.ResponseWriter, request *http.Request, name string, modified time.Time, body []byte) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Disposition", "inline")
	http.ServeContent(writer, request, name, modified, bytes.NewReader(body))
}

func (server *Server) authorize(writer http.ResponseWriter, request *http.Request, body []byte, adminOnly bool) (api.Key, string, bool) {
	fail := func(reason string) (api.Key, string, bool) {
		server.config.Logger.Warn("authentication rejected", "reason", reason, "remote", request.RemoteAddr, "path", request.URL.Path)
		writeError(writer, http.StatusUnauthorized, "authentication failed")
		return api.Key{}, "", false
	}
	keyID := request.Header.Get(protocol.HeaderKeyID)
	nonce := request.Header.Get(protocol.HeaderNonce)
	timestampValue := request.Header.Get(protocol.HeaderTimestamp)
	signatureValue := request.Header.Get(protocol.HeaderSignature)
	if keyID == "" || nonce == "" || timestampValue == "" || signatureValue == "" {
		return fail("missing headers")
	}
	if !protocol.IsUUIDv7(nonce) {
		return fail("invalid nonce")
	}
	timestamp, err := strconv.ParseInt(timestampValue, 10, 64)
	if err != nil {
		return fail("invalid timestamp")
	}
	now := server.config.Now()
	requestTime := time.Unix(timestamp, 0)
	if requestTime.Before(now.Add(-5*time.Minute)) || requestTime.After(now.Add(5*time.Minute)) {
		return fail("timestamp outside allowed window")
	}
	publicKey, key, found := server.keys.PublicKey(keyID)
	if !found {
		return fail("unknown key")
	}
	if adminOnly && key.Role != RoleAdmin {
		return fail("admin key required")
	}
	signature, err := protocol.DecodeSignature(signatureValue)
	if err != nil {
		return fail("invalid signature encoding")
	}
	canonical := protocol.Canonical(request.Method, request.URL.EscapedPath(), timestamp, nonce, body)
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fail("invalid signature")
	}
	if !server.useNonce(keyID, nonce, now) {
		return fail("replayed nonce")
	}
	return key, nonce, true
}

func (server *Server) useNonce(keyID, nonce string, now time.Time) bool {
	server.nonces.Lock()
	defer server.nonces.Unlock()
	cutoff := now.Add(-10 * time.Minute)
	for existing, usedAt := range server.nonces.used {
		if usedAt.Before(cutoff) {
			delete(server.nonces.used, existing)
		}
	}
	key := keyID + ":" + nonce
	if _, exists := server.nonces.used[key]; exists {
		return false
	}
	server.nonces.used[key] = now
	return true
}

func (server *Server) publicURL(request *http.Request) string {
	if server.config.PublicURL != "" {
		return server.config.PublicURL
	}
	scheme := request.Header.Get("X-Forwarded-Proto")
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + request.Host
}

var errContentConflict = errors.New("content conflict")

func writeImmutable(path string, body []byte) (bool, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return false, readErr
		}
		if string(existing) != string(body) {
			return false, errContentConflict
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	name := file.Name()
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return false, err
	}
	if err := file.Sync(); err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	ok = true
	return true, nil
}

func readBody(writer http.ResponseWriter, request *http.Request, maxBytes int64) ([]byte, bool) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(writer, http.StatusRequestEntityTooLarge, "request body is too large")
		} else {
			writeError(writer, http.StatusBadRequest, "could not read request body")
		}
		return nil, false
	}
	return body, true
}

func methodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, api.ErrorResponse{Error: message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(value)
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		next.ServeHTTP(writer, request)
		server.config.Logger.Info("request", "method", request.Method, "path", request.URL.Path, "duration", time.Since(started), "remote", request.RemoteAddr)
	})
}

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="11" fill="#171816"/>
<path d="M16 47V17h14c9 0 14 4.6 14 12s-5 12-14 12h-6v6h-8Zm8-14h6c4 0 6-1.3 6-4s-2-4-6-4h-6v8Z" fill="#eee9dc"/>
<path d="m42 43 6-6 6 6m-6-6v13" fill="none" stroke="#c9ff3d" stroke-width="4" stroke-linecap="square" stroke-linejoin="miter"/>
<circle cx="14" cy="51" r="4" fill="#ff5538"/>
</svg>`

const landingHTML = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0c0d0e">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<title>Pageup</title>
<style>
  :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0c0d0e; color: #ede7d9; }
  main { width: min(42rem, calc(100% - 3rem)); }
  h1 { font-size: clamp(2.8rem, 10vw, 6rem); letter-spacing: -.08em; margin: 0 0 1rem; }
  p { color: #a9a49a; line-height: 1.65; }
  code { display: block; overflow-x: auto; padding: 1rem; border: 1px solid #34322e; background: #151616; color: #b9f5a8; }
  .dot { color: #f7a65a; }
</style>
<main>
  <h1>pageup<span class="dot">.</span></h1>
  <p>Shareable, unlisted HTML pages for the Whagons team.</p>
  <code>curl -fsSL {{.URL}}/install.sh | sh<br>pageup auth login</code>
</main>
</html>`

func (server *Server) handleLanding(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	template.Must(template.New("landing").Parse(landingHTML)).Execute(writer, map[string]string{"URL": server.config.PublicURL})
}
