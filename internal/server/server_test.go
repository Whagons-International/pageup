package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/desarso/pageup/internal/api"
	pageclient "github.com/desarso/pageup/internal/client"
	"github.com/desarso/pageup/internal/protocol"
	"github.com/desarso/pageup/internal/sitebundle"
)

type testEnvironment struct {
	server     *httptest.Server
	privateKey ed25519.PrivateKey
	config     pageclient.Config
	dataDir    string
	now        time.Time
}

func newTestEnvironment(t *testing.T, maxBytes int64) testEnvironment {
	return newTestEnvironmentWithAuthorizer(t, maxBytes, nil)
}

func newTestEnvironmentWithAuthorizer(t *testing.T, maxBytes int64, authorizer DeveloperAuthorizer) testEnvironment {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	dataDir := t.TempDir()
	bootstrap, err := json.Marshal([]api.Key{{
		Name:      "test admin",
		PublicKey: protocol.EncodePublicKey(publicKey),
		Role:      RoleAdmin,
	}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		DataDir:       dataDir,
		BootstrapKeys: string(bootstrap),
		MaxPageBytes:  maxBytes,
		Version:       "test",
		Now:           time.Now,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authorizer:    authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(service.Handler())
	config := pageclient.Config{
		Version:    1,
		Endpoint:   httpServer.URL,
		KeyID:      protocol.KeyID(publicKey),
		PrivateKey: protocol.EncodePrivateKey(privateKey),
		Name:       "test admin",
	}
	return testEnvironment{server: httpServer, privateKey: privateKey, config: config, dataDir: dataDir, now: now}
}

type fakeDeveloperAuthorizer struct {
	identity DeveloperIdentity
	err      error
	token    string
}

func (authorizer *fakeDeveloperAuthorizer) Authorize(_ context.Context, token string) (DeveloperIdentity, error) {
	authorizer.token = token
	return authorizer.identity, authorizer.err
}

func TestGoogleDeviceAuthAuthorizesUploadOnlyKey(t *testing.T) {
	authorizer := &fakeDeveloperAuthorizer{identity: DeveloperIdentity{UserID: "firebase-dev", Email: "dev@whagons.com"}}
	environment := newTestEnvironmentWithAuthorizer(t, 1<<20, authorizer)
	defer environment.close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := pageclient.Config{
		Version:    1,
		Endpoint:   environment.server.URL,
		KeyID:      protocol.KeyID(publicKey),
		PrivateKey: protocol.EncodePrivateKey(privateKey),
		Name:       "Matas laptop",
	}
	deviceClient, err := pageclient.New(clientConfig, "test")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := deviceClient.StartDeviceAuth(context.Background(), clientConfig.Name, protocol.EncodePublicKey(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.IsUUIDv7(flow.ID) || flow.IntervalSeconds != 2 || normalizeUserCode(flow.UserCode) != flow.UserCode || flow.VerificationURI != environment.server.URL+"/auth" || flow.VerificationURL != environment.server.URL+"/auth/device/"+flow.ID || flow.VerificationURLComplete != environment.server.URL+"/auth?code="+flow.UserCode {
		t.Fatalf("flow = %#v", flow)
	}
	codePage, err := http.Get(flow.VerificationURI)
	if err != nil {
		t.Fatal(err)
	}
	codePageBody, _ := io.ReadAll(codePage.Body)
	codePage.Body.Close()
	if codePage.StatusCode != http.StatusOK || !strings.Contains(string(codePageBody), "Device code") || !strings.Contains(string(codePageBody), "XXXX-XXXX") {
		t.Fatalf("code page = %d %q", codePage.StatusCode, codePageBody)
	}
	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	codeResponse, err := noRedirect.PostForm(flow.VerificationURI, url.Values{"code": {strings.ToLower(strings.ReplaceAll(flow.UserCode, "-", ""))}})
	if err != nil {
		t.Fatal(err)
	}
	codeResponse.Body.Close()
	if codeResponse.StatusCode != http.StatusSeeOther || codeResponse.Header.Get("Location") != "/auth/device/"+flow.ID {
		t.Fatalf("code redirect = %d %q", codeResponse.StatusCode, codeResponse.Header.Get("Location"))
	}

	page, err := http.Get(flow.VerificationURL)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(pageBody), "Matas laptop") || !strings.Contains(string(pageBody), "Continue with Google") {
		t.Fatalf("authorization page = %d %q", page.StatusCode, pageBody)
	}
	if policy := page.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "https://apis.google.com") {
		t.Fatalf("authorization page CSP blocks Firebase popup helper: %q", policy)
	}
	status, err := deviceClient.DeviceAuthStatus(context.Background(), flow.ID)
	if err != nil || status.Status != deviceAuthPending {
		t.Fatalf("pending status = %#v, err = %v", status, err)
	}

	completeBody, _ := json.Marshal(api.DeviceAuthCompleteRequest{IDToken: "firebase-id-token"})
	response, err := http.Post(environment.server.URL+"/api/auth/device/"+flow.ID+"/complete", "application/json", bytes.NewReader(completeBody))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || authorizer.token != "firebase-id-token" {
		t.Fatalf("complete status = %d, token = %q", response.StatusCode, authorizer.token)
	}
	status, err = deviceClient.DeviceAuthStatus(context.Background(), flow.ID)
	if err != nil || status.Status != deviceAuthApproved || status.Email != "dev@whagons.com" {
		t.Fatalf("approved status = %#v, err = %v", status, err)
	}

	upload, err := deviceClient.Upload(context.Background(), []byte("<h1>team page</h1>"))
	if err != nil || !upload.Created {
		t.Fatalf("authorized upload = %#v, err = %v", upload, err)
	}
	if _, err := deviceClient.ListKeys(context.Background()); apiErrorStatus(err) != http.StatusUnauthorized {
		t.Fatalf("Google-authorized key could manage keys: %v", err)
	}
}

func TestGoogleDeviceAuthRejectsNonDeveloper(t *testing.T) {
	authorizer := &fakeDeveloperAuthorizer{err: errDeveloperAccessRequired}
	environment := newTestEnvironmentWithAuthorizer(t, 1<<20, authorizer)
	defer environment.close()

	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	clientConfig := pageclient.Config{Version: 1, Endpoint: environment.server.URL, KeyID: protocol.KeyID(publicKey), PrivateKey: protocol.EncodePrivateKey(mustPrivateKey(t)), Name: "Unknown laptop"}
	privateKey, err := protocol.DecodePrivateKey(clientConfig.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.KeyID = protocol.KeyID(privateKey.Public().(ed25519.PublicKey))
	deviceClient, err := pageclient.New(clientConfig, "test")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := deviceClient.StartDeviceAuth(context.Background(), clientConfig.Name, protocol.EncodePublicKey(privateKey.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.DeviceAuthCompleteRequest{IDToken: "not-a-developer"})
	response, err := http.Post(environment.server.URL+"/api/auth/device/"+flow.ID+"/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("complete status = %d", response.StatusCode)
	}
	status, err := deviceClient.DeviceAuthStatus(context.Background(), flow.ID)
	if err != nil || status.Status != deviceAuthDenied {
		t.Fatalf("denied status = %#v, err = %v", status, err)
	}
}

func TestDeviceAuthUserCodeFormat(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		code, err := newUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 9 || code[4] != '-' || normalizeUserCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))) != code {
			t.Fatalf("invalid device code %q", code)
		}
		if seen[code] {
			t.Fatalf("duplicate device code %q", code)
		}
		seen[code] = true
	}
	for _, invalid := range []string{"", "ABCD", "ABCD-IO10", "ABCD-EFGH-more"} {
		if normalized := normalizeUserCode(invalid); normalized != "" {
			t.Fatalf("normalizeUserCode(%q) = %q", invalid, normalized)
		}
	}
}

func TestInstallersCoverWindowsAndUnix(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()

	tests := []struct {
		path     string
		expected []string
	}{
		{"/install.sh", []string{"mingw*|msys*|cygwin*|windows_nt", "os=windows; suffix=.exe", "pageup-$os-$arch$suffix", "$HOME/bin/pageup-whagons.exe", "$HOME/.local/bin/pageup-whagons", "pageup-whagons auth login"}},
		{"/install.ps1", []string{"pageup-windows-$Arch.exe", "Programs\\pageup-whagons", "pageup-whagons.exe", "pageup-whagons auth login"}},
		{"/", []string{"macOS / Linux", "Windows PowerShell", "/install.ps1 | iex", "pageup-whagons auth login", "data-platform=\"windows\""}},
	}
	for _, test := range tests {
		response, err := http.Get(environment.server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, %v", test.path, response.StatusCode, readErr)
		}
		for _, expected := range test.expected {
			if !strings.Contains(string(body), expected) {
				t.Errorf("GET %s missing %q", test.path, expected)
			}
		}
	}
}

func mustPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func (environment testEnvironment) close() {
	environment.server.Close()
}

func addUploadClient(t *testing.T, admin *pageclient.Client, endpoint, name string) (*pageclient.Client, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := admin.AddKey(context.Background(), api.AddKeyRequest{
		Name:      name,
		PublicKey: protocol.EncodePublicKey(publicKey),
		Role:      RoleUpload,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := pageclient.New(pageclient.Config{
		Version:    1,
		Endpoint:   endpoint,
		KeyID:      key.ID,
		PrivateKey: protocol.EncodePrivateKey(privateKey),
		Name:       name,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return client, key.ID
}

func apiErrorStatus(err error) int {
	var apiError *pageclient.APIError
	if errors.As(err, &apiError) {
		return apiError.StatusCode
	}
	return 0
}

func TestUploadRequiresSignatureAndServesPageWithoutCaching(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()

	unsigned, err := http.Post(environment.server.URL+"/api/pages", "text/html", strings.NewReader("<h1>no</h1>"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d", unsigned.StatusCode)
	}

	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Upload(context.Background(), []byte("<!doctype html><h1>hello</h1>"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.Updated || result.Revision != 1 || !strings.HasPrefix(result.URL, environment.server.URL+"/") {
		t.Fatalf("unexpected upload result: %#v", result)
	}

	response, err := http.Get(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "<!doctype html><h1>hello</h1>" {
		t.Fatalf("page response %d %q", response.StatusCode, body)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected cache header %q", response.Header.Get("Cache-Control"))
	}
	metadataInfo, err := os.Stat(environment.dataDir + "/pages/" + result.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if metadataInfo.Mode().Perm() != 0o600 {
		t.Fatalf("page metadata mode = %o", metadataInfo.Mode().Perm())
	}
}

func TestUpdateRequiresSignatureAndKeepsURL(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := admin.Upload(context.Background(), []byte("<h1>first</h1>"))
	if err != nil {
		t.Fatal(err)
	}

	unsigned, _ := http.NewRequest(http.MethodPut, environment.server.URL+"/api/pages/"+upload.ID, strings.NewReader("<h1>no</h1>"))
	unsigned.Header.Set("Content-Type", "text/html")
	response, err := http.DefaultClient.Do(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned update status = %d", response.StatusCode)
	}

	updated, err := admin.Update(context.Background(), upload.ID, []byte("<h1>second</h1>"))
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != upload.ID || updated.URL != upload.URL || updated.Created || !updated.Updated || updated.Revision != 2 {
		t.Fatalf("unexpected update result: %#v", updated)
	}

	response, err = http.Get(upload.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || string(body) != "<h1>second</h1>" {
		t.Fatalf("updated page response %d %q", response.StatusCode, body)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("updated page cache header = %q", response.Header.Get("Cache-Control"))
	}

	unchanged, err := admin.Update(context.Background(), upload.ID, []byte("<h1>second</h1>"))
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Updated || unchanged.Revision != 2 || unchanged.URL != upload.URL {
		t.Fatalf("unexpected unchanged result: %#v", unchanged)
	}
	missingID, err := protocol.NewUUIDv7(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Update(context.Background(), missingID, []byte("missing")); apiErrorStatus(err) != http.StatusNotFound {
		t.Fatalf("missing page update error = %v", err)
	}
}

func TestHTMLSiteUploadServesNestedPagesAndDirectoryIndexes(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeSiteFile(t, root, "index.html", `<a href="about.html">About</a><a href="docs/">Docs</a>`)
	writeSiteFile(t, root, "about.html", `<h1>About</h1>`)
	writeSiteFile(t, root, "docs/index.html", `<h1>Docs</h1>`)
	archive, err := sitebundle.Pack(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.UploadSite(context.Background(), archive)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || !strings.HasSuffix(result.URL, "/") {
		t.Fatalf("unexpected site upload result: %#v", result)
	}
	assertHTMLResponse(t, result.URL, `<a href="about.html">About</a><a href="docs/">Docs</a>`)
	assertHTMLResponse(t, result.URL+"about.html", `<h1>About</h1>`)
	assertHTMLResponse(t, result.URL+"docs/", `<h1>Docs</h1>`)

	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	for _, value := range []string{strings.TrimSuffix(result.URL, "/"), result.URL + "docs"} {
		response, err := noRedirect.Get(value)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusPermanentRedirect || !strings.HasSuffix(response.Header.Get("Location"), "/") {
			t.Fatalf("redirect for %s = %d, location %q", value, response.StatusCode, response.Header.Get("Location"))
		}
	}

	if _, err := os.Stat(filepath.Join(environment.dataDir, "pages", result.ID+".site.zip")); err != nil {
		t.Fatal(err)
	}
	if response, err := http.Get(result.URL + "missing.html"); err != nil {
		t.Fatal(err)
	} else {
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("missing site page status = %d", response.StatusCode)
		}
	}
}

func TestHTMLSiteUpdatesAndCanConvertToSinglePage(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeSiteFile(t, root, "index.html", "site revision 1")
	first, err := sitebundle.Pack(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := client.UploadSite(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}

	unchanged, err := client.UpdateSite(context.Background(), upload.ID, first)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Updated || unchanged.Revision != 1 || unchanged.URL != upload.URL {
		t.Fatalf("unchanged site update = %#v", unchanged)
	}

	writeSiteFile(t, root, "index.html", "site revision 2")
	second, err := sitebundle.Pack(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.UpdateSite(context.Background(), upload.ID, second)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Updated || updated.Revision != 2 || !strings.HasSuffix(updated.URL, "/") {
		t.Fatalf("site update = %#v", updated)
	}
	assertHTMLResponse(t, upload.URL, "site revision 2")

	single, err := client.Update(context.Background(), upload.ID, []byte("single revision 3"))
	if err != nil {
		t.Fatal(err)
	}
	if !single.Updated || single.Revision != 3 || strings.HasSuffix(single.URL, "/") {
		t.Fatalf("site-to-page update = %#v", single)
	}
	assertHTMLResponse(t, single.URL, "single revision 3")
	if _, err := os.Stat(filepath.Join(environment.dataDir, "pages", upload.ID+".site.zip")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old site archive still exists: %v", err)
	}
}

func TestHTMLSiteUploadRejectsInvalidArchive(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UploadSite(context.Background(), []byte("not a ZIP archive")); apiErrorStatus(err) != http.StatusBadRequest {
		t.Fatalf("invalid site upload error = %v", err)
	}
}

func TestConcurrentUpdatesAreSerialized(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := admin.Upload(context.Background(), []byte("revision 1"))
	if err != nil {
		t.Fatal(err)
	}

	type updateResult struct {
		response api.UploadResponse
		err      error
	}
	results := make(chan updateResult, 2)
	for _, body := range [][]byte{[]byte("revision alpha"), []byte("revision beta")} {
		body := body
		go func() {
			response, err := admin.Update(context.Background(), upload.ID, body)
			results <- updateResult{response: response, err: err}
		}()
	}
	revisions := make(map[uint64]bool)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.response.Updated {
			t.Fatalf("concurrent update was not marked updated: %#v", result.response)
		}
		revisions[result.response.Revision] = true
	}
	if !revisions[2] || !revisions[3] || len(revisions) != 2 {
		t.Fatalf("concurrent revisions = %#v", revisions)
	}
	metadata, err := readPageMetadata(environment.dataDir+"/pages/"+upload.ID+".json", upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Revision != 3 {
		t.Fatalf("stored revision = %d", metadata.Revision)
	}
}

func TestPageOwnersAndAdminsCanUpdate(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	owner, ownerID := addUploadClient(t, admin, environment.server.URL, "owner")
	other, _ := addUploadClient(t, admin, environment.server.URL, "other")

	upload, err := owner.Upload(context.Background(), []byte("owner revision 1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Update(context.Background(), upload.ID, []byte("owner revision 2")); err != nil {
		t.Fatalf("owner update failed: %v", err)
	}
	if _, err := other.Update(context.Background(), upload.ID, []byte("not allowed")); apiErrorStatus(err) != http.StatusForbidden {
		t.Fatalf("other key update error = %v", err)
	}
	adminUpdate, err := admin.Update(context.Background(), upload.ID, []byte("admin revision 3"))
	if err != nil {
		t.Fatalf("admin update failed: %v", err)
	}
	if adminUpdate.Revision != 3 {
		t.Fatalf("admin update revision = %d", adminUpdate.Revision)
	}

	metadata, err := readPageMetadata(environment.dataDir+"/pages/"+upload.ID+".json", upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.OwnerKeyID != ownerID {
		t.Fatalf("admin update changed owner from %s to %s", ownerID, metadata.OwnerKeyID)
	}
}

func TestLegacyPagesAreAdminOnlyAndBecomeOwned(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	uploader, _ := addUploadClient(t, admin, environment.server.URL, "uploader")
	id, err := protocol.NewUUIDv7(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	htmlPath := environment.dataDir + "/pages/" + id + ".html"
	if err := os.WriteFile(htmlPath, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := uploader.Update(context.Background(), id, []byte("denied")); apiErrorStatus(err) != http.StatusForbidden {
		t.Fatalf("legacy uploader update error = %v", err)
	}
	updated, err := admin.Update(context.Background(), id, []byte("migrated"))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Updated || updated.Revision != 2 {
		t.Fatalf("legacy update result = %#v", updated)
	}
	metadata, err := readPageMetadata(environment.dataDir+"/pages/"+id+".json", id)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.OwnerKeyID != environment.config.KeyID {
		t.Fatalf("legacy owner = %q", metadata.OwnerKeyID)
	}
}

func TestLandingPublishesSiteFavicon(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()

	landing, err := http.Get(environment.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	landingBody, err := io.ReadAll(landing.Body)
	landing.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if landing.StatusCode != http.StatusOK || !strings.Contains(string(landingBody), `href="/favicon.svg"`) {
		t.Fatalf("landing status = %d, favicon link missing", landing.StatusCode)
	}

	favicon, err := http.Get(environment.server.URL + "/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	faviconBody, err := io.ReadAll(favicon.Body)
	favicon.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if favicon.StatusCode != http.StatusOK {
		t.Fatalf("favicon status = %d", favicon.StatusCode)
	}
	if favicon.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("favicon content type = %q", favicon.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(faviconBody), `<svg`) || !strings.Contains(string(faviconBody), `#c9ff3d`) {
		t.Fatal("favicon response does not contain the Pageup SVG")
	}

	head, err := http.Head(environment.server.URL + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK || head.Header.Get("Content-Length") == "" {
		t.Fatalf("favicon fallback HEAD status = %d, length = %q", head.StatusCode, head.Header.Get("Content-Length"))
	}
}

func TestTamperedAndReplayedRequestsAreRejected(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	nonce, _ := protocol.NewUUIDv7(environment.now)
	original := []byte("<p>original</p>")

	tampered, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/pages", bytes.NewReader([]byte("<p>tampered</p>")))
	tampered.Header.Set("Content-Type", "text/html")
	protocol.SignRequest(tampered, environment.privateKey, nonce, original, environment.now)
	response, err := http.DefaultClient.Do(tampered)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered status = %d", response.StatusCode)
	}

	expiredNonce, _ := protocol.NewUUIDv7(environment.now.Add(2 * time.Millisecond))
	expired, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/pages", bytes.NewReader(original))
	expired.Header.Set("Content-Type", "text/html")
	protocol.SignRequest(expired, environment.privateKey, expiredNonce, original, environment.now.Add(-6*time.Minute))
	response, err = http.DefaultClient.Do(expired)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired status = %d", response.StatusCode)
	}

	nonce, _ = protocol.NewUUIDv7(environment.now.Add(time.Millisecond))
	request, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/pages", bytes.NewReader(original))
	request.Header.Set("Content-Type", "text/html")
	protocol.SignRequest(request, environment.privateKey, nonce, original, environment.now)
	headers := request.Header.Clone()
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("first status = %d", response.StatusCode)
	}

	replay, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/pages", bytes.NewReader(original))
	replay.Header = headers
	response, err = http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d", response.StatusCode)
	}
}

func TestPerDeviceRolesAndKeyManagement(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	adminClient, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	uploadPublic, uploadPrivate, _ := ed25519.GenerateKey(rand.Reader)
	added, err := adminClient.AddKey(context.Background(), api.AddKeyRequest{
		Name:      "upload laptop",
		PublicKey: protocol.EncodePublicKey(uploadPublic),
		Role:      RoleUpload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if added.Role != RoleUpload {
		t.Fatalf("role = %s", added.Role)
	}
	uploadConfig := pageclient.Config{
		Version:    1,
		Endpoint:   environment.server.URL,
		KeyID:      protocol.KeyID(uploadPublic),
		PrivateKey: protocol.EncodePrivateKey(uploadPrivate),
	}
	uploadClient, err := pageclient.New(uploadConfig, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uploadClient.Upload(context.Background(), []byte("<p>allowed</p>")); err != nil {
		t.Fatalf("upload key could not upload: %v", err)
	}
	if _, err := uploadClient.ListKeys(context.Background()); err == nil {
		t.Fatal("upload key unexpectedly listed keys")
	}
	if _, err := adminClient.RevokeKey(context.Background(), environment.config.KeyID); err == nil {
		t.Fatal("last admin was unexpectedly revoked")
	}
	keys, err := adminClient.ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("key count = %d", len(keys))
	}
}

func TestUploadSizeLimit(t *testing.T) {
	environment := newTestEnvironment(t, 16)
	defer environment.close()
	nonce, _ := protocol.NewUUIDv7(environment.now)
	body := bytes.Repeat([]byte("x"), 17)
	request, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/pages", bytes.NewReader(body))
	request.Header.Set("Content-Type", "text/html")
	protocol.SignRequest(request, environment.privateKey, nonce, body, environment.now)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", response.StatusCode)
	}

	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := client.Upload(context.Background(), []byte("small"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Update(context.Background(), upload.ID, body); apiErrorStatus(err) != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized update error = %v", err)
	}
}

func TestKeyStorePersists(t *testing.T) {
	directory := t.TempDir()
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	bootstrap, _ := json.Marshal([]api.Key{{Name: "admin", PublicKey: protocol.EncodePublicKey(publicKey), Role: RoleAdmin}})
	now := time.Now().UTC()
	store, err := NewKeyStore(directory+"/keys.json", string(bootstrap), now)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := store.Add("second", secondPublic, RoleUpload, now); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewKeyStore(directory+"/keys.json", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.List()) != 2 {
		t.Fatalf("persisted key count = %d", len(reloaded.List()))
	}
	info, err := os.Stat(directory + "/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key store mode = %o", info.Mode().Perm())
	}
}

func writeSiteFile(t *testing.T, root, name, contents string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertHTMLResponse(t *testing.T, url, expected string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || string(body) != expected {
		t.Fatalf("GET %s = %d %q", url, response.StatusCode, body)
	}
	if response.Header.Get("Content-Type") != "text/html; charset=utf-8" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET %s headers: content-type=%q cache-control=%q", url, response.Header.Get("Content-Type"), response.Header.Get("Cache-Control"))
	}
}
