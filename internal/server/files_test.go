package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/desarso/pageup/internal/api"
	pageclient "github.com/desarso/pageup/internal/client"
	"github.com/desarso/pageup/internal/protocol"
)

var noRedirectClient = &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

func uploadTestFile(t *testing.T, client *pageclient.Client, name, contents string) api.FileResponse {
	t.Helper()
	result, err := client.UploadFile(context.Background(), name, strings.NewReader(contents))
	if err != nil {
		t.Fatalf("upload %s: %v", name, err)
	}
	return result
}

func getFile(t *testing.T, target string, header http.Header) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := noRedirectClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func storedFileEntries(t *testing.T, dataDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dataDir, "files"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestFileUploadStreamsAndServesInline(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()

	contents := "hello, shared file"
	sum := sha256.Sum256([]byte(contents))
	unsigned, err := http.NewRequest(http.MethodPost, environment.server.URL+"/api/files/notes.txt", strings.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Header.Set(protocol.HeaderContentSHA256, hex.EncodeToString(sum[:]))
	response, err := http.DefaultClient.Do(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d", response.StatusCode)
	}

	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	result := uploadTestFile(t, client, "notes.txt", contents)
	if !result.Created || result.Updated || result.Revision != 1 || result.Size != int64(len(contents)) ||
		result.SHA256 != hex.EncodeToString(sum[:]) || result.ContentType != "text/plain; charset=utf-8" ||
		result.URL != environment.server.URL+"/f/"+result.ID+"/notes.txt" || !protocol.IsUUIDv7(result.ID) {
		t.Fatalf("upload result = %#v", result)
	}

	response, body := getFile(t, result.URL, nil)
	if response.StatusCode != http.StatusOK || body != contents {
		t.Fatalf("GET = %d %q", response.StatusCode, body)
	}
	for name, expected := range map[string]string{
		"Content-Type":                "text/plain; charset=utf-8",
		"Content-Disposition":         "inline; filename=notes.txt",
		"Cache-Control":               "no-cache",
		"ETag":                        `"` + result.SHA256 + `"`,
		"Access-Control-Allow-Origin": "*",
		"X-Content-Type-Options":      "nosniff",
	} {
		if actual := response.Header.Get(name); actual != expected {
			t.Fatalf("%s = %q, want %q", name, actual, expected)
		}
	}

	response, _ = getFile(t, result.URL+"?download", nil)
	if response.Header.Get("Content-Disposition") != "attachment; filename=notes.txt" {
		t.Fatalf("download disposition = %q", response.Header.Get("Content-Disposition"))
	}
	response, body = getFile(t, result.URL, http.Header{"Range": {"bytes=7-"}})
	if response.StatusCode != http.StatusPartialContent || body != contents[7:] {
		t.Fatalf("range = %d %q", response.StatusCode, body)
	}
	response, _ = getFile(t, result.URL, http.Header{"If-None-Match": {`"` + result.SHA256 + `"`}})
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional status = %d", response.StatusCode)
	}
	for _, target := range []string{"/f/" + result.ID, "/f/" + result.ID + "/", "/f/" + result.ID + "/renamed.txt?download"} {
		response, _ = getFile(t, environment.server.URL+target, nil)
		expected := "/f/" + result.ID + "/notes.txt"
		if strings.HasSuffix(target, "?download") {
			expected += "?download"
		}
		if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != expected {
			t.Fatalf("GET %s = %d %q", target, response.StatusCode, response.Header.Get("Location"))
		}
	}

	info, err := os.Stat(filepath.Join(environment.dataDir, "files", result.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file metadata mode = %o", info.Mode().Perm())
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 2 {
		t.Fatalf("stored entries = %v", entries)
	}
}

func TestFileNamesAreEscapedAndValidated(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}

	name := "Screenshot 2026-09-25 at 10.00.00 AM (1).png"
	result := uploadTestFile(t, client, name, "\x89PNG\r\n\x1a\n")
	if result.Name != name || result.URL != environment.server.URL+"/f/"+result.ID+"/"+url.PathEscape(name) {
		t.Fatalf("result = %#v", result)
	}
	response, _ := getFile(t, result.URL, nil)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/png" ||
		!strings.HasPrefix(response.Header.Get("Content-Disposition"), "inline; filename*=utf-8''Screenshot%202026") {
		t.Fatalf("GET = %d %q %q", response.StatusCode, response.Header.Get("Content-Type"), response.Header.Get("Content-Disposition"))
	}

	for _, escaped := range []string{"..", "a%2Fb.txt", "a%5Cb.txt", "bad%0Aname.txt", "%ff.txt", strings.Repeat("x", 256)} {
		body := []byte("x")
		nonce, _ := protocol.NewUUIDv7(environment.now)
		request, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/files/"+escaped, bytes.NewReader(body))
		request.Header.Set(protocol.HeaderContentSHA256, protocol.BodyHash(body))
		protocol.SignRequestHash(request, environment.privateKey, nonce, protocol.BodyHash(body), environment.now)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode < 400 || response.StatusCode >= 500 {
			t.Fatalf("name %q status = %d", escaped, response.StatusCode)
		}
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 2 {
		t.Fatalf("invalid names were stored: %v", entries)
	}
}

func TestFileContentTypesAndDisposition(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, contents, contentType, disposition string
	}{
		{"photo.png", "\x89PNG\r\n\x1a\n", "image/png", "inline"},
		{"clip.mp4", "video", "video/mp4", "inline"},
		{"report.pdf", "%PDF-1.7", "application/pdf", "inline"},
		{"data.json", `{"ok":true}`, "application/json", "inline"},
		{"page.html", "<script>alert(1)</script>", "text/html; charset=utf-8", "attachment"},
		{"logo.svg", "<svg onload=alert(1)>", "image/svg+xml", "attachment"},
		{"bundle.zip", "PK\x03\x04", "application/zip", "attachment"},
		{"Makefile", "build:\n\tgo build\n", "text/plain; charset=utf-8", "inline"},
		{"payload", "<!doctype html><script>alert(1)</script>", "text/html; charset=utf-8", "attachment"},
	} {
		result := uploadTestFile(t, client, test.name, test.contents)
		response, body := getFile(t, result.URL, nil)
		if response.StatusCode != http.StatusOK || body != test.contents || result.ContentType != test.contentType ||
			response.Header.Get("Content-Type") != test.contentType ||
			!strings.HasPrefix(response.Header.Get("Content-Disposition"), test.disposition+";") {
			t.Fatalf("%s = %d type=%q/%q disposition=%q", test.name, response.StatusCode, result.ContentType, response.Header.Get("Content-Type"), response.Header.Get("Content-Disposition"))
		}
	}
}

func TestFileUploadVerifiesBodyAndLimits(t *testing.T) {
	environment := newTestEnvironmentWithConfig(t, Config{MaxFileBytes: 16})
	defer environment.close()

	send := func(body []byte, signedHash, headerHash string, configure func(*http.Request)) int {
		t.Helper()
		nonce, _ := protocol.NewUUIDv7(environment.now)
		request, _ := http.NewRequest(http.MethodPost, environment.server.URL+"/api/files/data.bin", bytes.NewReader(body))
		if configure != nil {
			configure(request)
		}
		request.Header.Set(protocol.HeaderContentSHA256, headerHash)
		protocol.SignRequestHash(request, environment.privateKey, nonce, signedHash, environment.now)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	original := []byte("original")
	tampered := []byte("tampered")
	if status := send(tampered, protocol.BodyHash(original), protocol.BodyHash(original), nil); status != http.StatusBadRequest {
		t.Fatalf("mismatched body status = %d", status)
	}
	if status := send(original, protocol.BodyHash(original), protocol.BodyHash(tampered), nil); status != http.StatusUnauthorized {
		t.Fatalf("mismatched header status = %d", status)
	}
	if status := send(original, protocol.BodyHash(original), "not-a-hash", nil); status != http.StatusBadRequest {
		t.Fatalf("invalid hash status = %d", status)
	}
	chunked := func(request *http.Request) {
		request.Body = io.NopCloser(bytes.NewReader(original))
		request.ContentLength = -1
	}
	if status := send(original, protocol.BodyHash(original), protocol.BodyHash(original), chunked); status != http.StatusLengthRequired {
		t.Fatalf("chunked status = %d", status)
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 0 {
		t.Fatalf("rejected uploads were stored: %v", entries)
	}

	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("x", 17)
	if _, err := client.UploadFile(context.Background(), "big.txt", strings.NewReader(oversized)); apiErrorStatus(err) != http.StatusRequestEntityTooLarge || !strings.Contains(err.Error(), "16 bytes") {
		t.Fatalf("oversized upload error = %v", err)
	}
	result := uploadTestFile(t, client, "small.txt", "small")
	if _, err := client.UpdateFile(context.Background(), result.ID, "", strings.NewReader(oversized)); apiErrorStatus(err) != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized update error = %v", err)
	}
	empty := uploadTestFile(t, client, "empty.txt", "")
	response, body := getFile(t, empty.URL, nil)
	if response.StatusCode != http.StatusOK || body != "" || empty.Size != 0 {
		t.Fatalf("empty file = %d %q %#v", response.StatusCode, body, empty)
	}
}

func TestFileUpdatesKeepURLAndEnforceOwnership(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := addUploadClient(t, admin, environment.server.URL, "owner")
	other, _ := addUploadClient(t, admin, environment.server.URL, "other")
	ctx := context.Background()

	created := uploadTestFile(t, owner, "report.txt", "v1")
	if _, err := other.UpdateFile(ctx, created.ID, "", strings.NewReader("stolen")); apiErrorStatus(err) != http.StatusForbidden {
		t.Fatalf("other update error = %v", err)
	}
	if _, err := other.DeleteFile(ctx, created.ID); apiErrorStatus(err) != http.StatusForbidden {
		t.Fatalf("other delete error = %v", err)
	}

	updated, err := owner.UpdateFile(ctx, created.ID, "", strings.NewReader("version two"))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Updated || updated.Revision != 2 || updated.URL != created.URL || updated.Size != 11 {
		t.Fatalf("update = %#v", updated)
	}
	if _, body := getFile(t, created.URL, nil); body != "version two" {
		t.Fatalf("updated body = %q", body)
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 2 {
		t.Fatalf("replaced content was kept: %v", entries)
	}

	unchanged, err := owner.UpdateFile(ctx, created.ID, "", strings.NewReader("version two"))
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Updated || unchanged.Revision != 2 {
		t.Fatalf("unchanged update = %#v", unchanged)
	}

	renamed, err := owner.UpdateFile(ctx, created.ID, "final.md", strings.NewReader("version two"))
	if err != nil {
		t.Fatal(err)
	}
	if !renamed.Updated || renamed.Revision != 3 || renamed.Name != "final.md" || renamed.ContentType != "text/markdown; charset=utf-8" ||
		renamed.URL != environment.server.URL+"/f/"+created.ID+"/final.md" {
		t.Fatalf("rename = %#v", renamed)
	}
	response, _ := getFile(t, created.URL, nil)
	if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != "/f/"+created.ID+"/final.md" {
		t.Fatalf("old name = %d %q", response.StatusCode, response.Header.Get("Location"))
	}

	byAdmin, err := admin.UpdateFile(ctx, created.ID, "", strings.NewReader("admin fix"))
	if err != nil || byAdmin.Revision != 4 {
		t.Fatalf("admin update = %#v, %v", byAdmin, err)
	}
	missing, _ := protocol.NewUUIDv7(environment.now)
	if _, err := owner.UpdateFile(ctx, missing, "", strings.NewReader("x")); apiErrorStatus(err) != http.StatusNotFound {
		t.Fatalf("missing update error = %v", err)
	}
}

func TestConcurrentFileUpdatesAreSerialized(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	created := uploadTestFile(t, client, "counter.txt", "0")

	const updates = 8
	var wait sync.WaitGroup
	errs := make(chan error, updates)
	for index := 1; index <= updates; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := client.UpdateFile(context.Background(), created.ID, "", strings.NewReader(strconv.Itoa(index)))
			errs <- err
		}(index)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	final, err := client.UpdateFile(context.Background(), created.ID, "", strings.NewReader("final"))
	if err != nil {
		t.Fatal(err)
	}
	if final.Revision != updates+2 {
		t.Fatalf("final revision = %d", final.Revision)
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 2 {
		t.Fatalf("stored entries after concurrent updates = %v", entries)
	}
}

func TestFileDeleteRemovesContent(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	admin, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := addUploadClient(t, admin, environment.server.URL, "owner")
	created := uploadTestFile(t, owner, "secret.env", "TOKEN=oops")

	deleted, err := owner.DeleteFile(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.ID != created.ID {
		t.Fatalf("delete = %#v", deleted)
	}
	if response, _ := getFile(t, created.URL, nil); response.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted GET = %d", response.StatusCode)
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 0 {
		t.Fatalf("deleted file left entries: %v", entries)
	}
	if _, err := owner.DeleteFile(context.Background(), created.ID); apiErrorStatus(err) != http.StatusNotFound {
		t.Fatalf("second delete error = %v", err)
	}
}

// fakeS3 is a path-style S3 endpoint that stores objects in memory and honors
// open-ended Range requests, like tg-s3.
type fakeS3 struct {
	mu        sync.Mutex
	objects   map[string][]byte
	maxObject int
}

func newFakeS3(t *testing.T) (*fakeS3, *s3ObjectStore) {
	t.Helper()
	fake := &fakeS3{objects: make(map[string][]byte)}
	endpoint := httptest.NewServer(fake)
	t.Cleanup(endpoint.Close)
	store, err := newS3ObjectStore(S3Config{
		Endpoint:        endpoint.URL,
		Bucket:          "pageup",
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return fake, store
}

func (fake *fakeS3) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/pageup" {
		writer.WriteHeader(http.StatusOK)
		return
	}
	key := strings.TrimPrefix(request.URL.Path, "/pageup/")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	switch request.Method {
	case http.MethodGet:
		body, ok := fake.objects[key]
		if !ok {
			writer.Header().Set("Content-Type", "application/xml")
			writer.WriteHeader(http.StatusNotFound)
			io.WriteString(writer, `<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`)
			return
		}
		writer.Header().Set("Last-Modified", "Wed, 27 Aug 2026 12:00:00 GMT")
		if value := request.Header.Get("Range"); value != "" {
			start, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(value, "bytes="), "-"))
			if err != nil || start >= len(body) {
				writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
			writer.WriteHeader(http.StatusPartialContent)
			writer.Write(body[start:])
			return
		}
		writer.Write(body)
	case http.MethodPut:
		body, _ := io.ReadAll(request.Body)
		if fake.maxObject > 0 && len(body) > fake.maxObject {
			writer.Header().Set("Content-Type", "application/xml")
			writer.WriteHeader(http.StatusBadRequest)
			io.WriteString(writer, `<Error><Code>EntityTooLarge</Code><Message>too large</Message></Error>`)
			return
		}
		fake.objects[key] = body
		writer.Header().Set("ETag", `"test"`)
		writer.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(fake.objects, key)
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (fake *fakeS3) keys() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	keys := make([]string, 0, len(fake.objects))
	for key := range fake.objects {
		keys = append(keys, key)
	}
	return keys
}

func TestFilesStreamThroughS3Storage(t *testing.T) {
	fake, store := newFakeS3(t)
	environment := newTestEnvironmentWithConfig(t, Config{storage: store, FileChunkBytes: 4096})
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}

	contents := strings.Repeat("0123456789", 1000)
	created := uploadTestFile(t, client, "digits.txt", contents)
	response, body := getFile(t, created.URL, nil)
	if response.StatusCode != http.StatusOK || body != contents {
		t.Fatalf("GET = %d len=%d", response.StatusCode, len(body))
	}
	response, body = getFile(t, created.URL, http.Header{"Range": {"bytes=9995-"}})
	if response.StatusCode != http.StatusPartialContent || body != "56789" {
		t.Fatalf("suffix range = %d %q", response.StatusCode, body)
	}
	response, body = getFile(t, created.URL, http.Header{"Range": {"bytes=10-14"}})
	if response.StatusCode != http.StatusPartialContent || body != "01234" {
		t.Fatalf("bounded range = %d %q", response.StatusCode, body)
	}
	response, body = getFile(t, created.URL, http.Header{"Range": {"bytes=4090-4105"}})
	if response.StatusCode != http.StatusPartialContent || body != contents[4090:4106] {
		t.Fatalf("cross-chunk range = %d %q", response.StatusCode, body)
	}
	chunkKeys := 0
	for _, key := range fake.keys() {
		if strings.HasPrefix(key, "files/"+created.ID+"."+created.ID+".") {
			chunkKeys++
		}
	}
	if chunkKeys != 3 {
		t.Fatalf("S3 chunk keys = %v", fake.keys())
	}

	if _, err := client.UpdateFile(context.Background(), created.ID, "", strings.NewReader("replaced")); err != nil {
		t.Fatal(err)
	}
	if _, body := getFile(t, created.URL, nil); body != "replaced" {
		t.Fatalf("updated body = %q", body)
	}
	fileKeys := 0
	for _, key := range fake.keys() {
		if strings.HasPrefix(key, "files/") {
			fileKeys++
		}
	}
	if fileKeys != 2 {
		t.Fatalf("S3 file keys = %v", fake.keys())
	}

	fake.mu.Lock()
	fake.maxObject = 4
	fake.mu.Unlock()
	if _, err := client.UploadFile(context.Background(), "big.txt", strings.NewReader("too large")); apiErrorStatus(err) != http.StatusRequestEntityTooLarge || !strings.Contains(err.Error(), "storage backend") {
		t.Fatalf("backend limit error = %v", err)
	}

	if _, err := client.DeleteFile(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	for _, key := range fake.keys() {
		if strings.HasPrefix(key, "files/") {
			t.Fatalf("deleted file left S3 key %s", key)
		}
	}
}

func TestUnauthorizedLargeFileUploadIsRejectedBeforeBody(t *testing.T) {
	environment := newTestEnvironment(t, 1<<20)
	defer environment.close()
	stranger := environment.config
	privateKey := mustPrivateKey(t)
	stranger.KeyID = protocol.KeyID(privateKey.Public().(ed25519.PublicKey))
	stranger.PrivateKey = protocol.EncodePrivateKey(privateKey)
	client, err := pageclient.New(stranger, "test")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingReader{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 8<<20))}
	if _, err := client.UploadFile(context.Background(), "big.bin", counted); apiErrorStatus(err) != http.StatusUnauthorized {
		t.Fatalf("stranger upload error = %v", err)
	}
	// The client reads the file once to hash it; Expect: 100-continue should
	// keep it from streaming the body to a server that already refused it.
	if counted.read > 9<<20 {
		t.Fatalf("client sent the rejected body: read %d bytes", counted.read)
	}
}

type countingReader struct {
	reader *bytes.Reader
	read   int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += int64(count)
	return count, err
}

func (reader *countingReader) Seek(offset int64, whence int) (int64, error) {
	return reader.reader.Seek(offset, whence)
}

func TestChunkedFilesReassembleAndCleanUp(t *testing.T) {
	environment := newTestEnvironmentWithConfig(t, Config{FileChunkBytes: 4})
	defer environment.close()
	client, err := pageclient.New(environment.config, "test")
	if err != nil {
		t.Fatal(err)
	}

	contents := "0123456789abcdef!"
	created := uploadTestFile(t, client, "chunks.txt", contents)
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 6 {
		t.Fatalf("stored entries = %v", entries)
	}
	response, body := getFile(t, created.URL, nil)
	if response.StatusCode != http.StatusOK || body != contents || response.Header.Get("Content-Length") != "17" {
		t.Fatalf("GET = %d %q", response.StatusCode, body)
	}
	for header, expected := range map[string]string{
		"bytes=3-9":   contents[3:10],
		"bytes=8-11":  contents[8:12],
		"bytes=16-":   "!",
		"bytes=-6":    contents[11:],
		"bytes=0-0":   "0",
		"bytes=5-100": contents[5:],
	} {
		response, body := getFile(t, created.URL, http.Header{"Range": {header}})
		if response.StatusCode != http.StatusPartialContent || body != expected {
			t.Fatalf("Range %s = %d %q, want %q", header, response.StatusCode, body, expected)
		}
	}
	response, body = getFile(t, created.URL, http.Header{"Range": {"bytes=0-1,4-5"}})
	if response.StatusCode != http.StatusPartialContent || !strings.Contains(body, "01") || !strings.Contains(body, "45") {
		t.Fatalf("multipart range = %d %q", response.StatusCode, body)
	}

	if _, err := client.UpdateFile(context.Background(), created.ID, "", strings.NewReader("tiny")); err != nil {
		t.Fatal(err)
	}
	if _, body := getFile(t, created.URL, nil); body != "tiny" {
		t.Fatalf("updated body = %q", body)
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 2 {
		t.Fatalf("entries after update = %v", entries)
	}
	empty := uploadTestFile(t, client, "empty.txt", "")
	if response, body := getFile(t, empty.URL, nil); response.StatusCode != http.StatusOK || body != "" {
		t.Fatalf("empty chunked file = %d %q", response.StatusCode, body)
	}
	for _, id := range []string{created.ID, empty.ID} {
		if _, err := client.DeleteFile(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if entries := storedFileEntries(t, environment.dataDir); len(entries) != 0 {
		t.Fatalf("entries after delete = %v", entries)
	}
}

func TestS3StorageDefaultsToChunkedFiles(t *testing.T) {
	fake := &fakeS3{objects: make(map[string][]byte)}
	endpoint := httptest.NewServer(fake)
	defer endpoint.Close()
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		BootstrapKeys: `[{"name":"admin","public_key":"` + protocol.EncodePublicKey(publicKey) + `","role":"admin"}]`,
		S3:            S3Config{Endpoint: endpoint.URL, Bucket: "pageup", AccessKeyID: "access", SecretAccessKey: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.config.FileChunkBytes != defaultS3FileChunkBytes {
		t.Fatalf("S3 chunk size = %d", service.config.FileChunkBytes)
	}
	disk, err := New(Config{DataDir: t.TempDir(), BootstrapKeys: service.config.BootstrapKeys})
	if err != nil {
		t.Fatal(err)
	}
	if disk.config.FileChunkBytes != 0 {
		t.Fatalf("filesystem chunk size = %d", disk.config.FileChunkBytes)
	}
}
