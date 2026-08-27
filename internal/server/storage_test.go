package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestS3ObjectStoreUsesPathStyleAndPrefix(t *testing.T) {
	var mu sync.Mutex
	objects := make(map[string][]byte)
	endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/pageup" && request.Method == http.MethodHead {
			writer.WriteHeader(http.StatusOK)
			return
		}
		const objectPrefix = "/pageup/team/"
		if !strings.HasPrefix(request.URL.Path, objectPrefix) {
			http.NotFound(writer, request)
			return
		}
		key := strings.TrimPrefix(request.URL.Path, objectPrefix)
		mu.Lock()
		defer mu.Unlock()
		switch request.Method {
		case http.MethodGet:
			body, ok := objects[key]
			if !ok {
				writer.Header().Set("Content-Type", "application/xml")
				writer.WriteHeader(http.StatusNotFound)
				io.WriteString(writer, `<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`)
				return
			}
			writer.Header().Set("Last-Modified", "Wed, 27 Aug 2026 12:00:00 GMT")
			writer.Write(body)
		case http.MethodPut:
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			objects[key] = body
			writer.Header().Set("ETag", `"test"`)
			writer.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(objects, key)
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer endpoint.Close()

	store, err := newS3ObjectStore(S3Config{
		Endpoint:        endpoint.URL,
		Region:          "us-east-1",
		Bucket:          "pageup",
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		Prefix:          "/team/",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Put("pages/test.html", []byte("first"), true)
	if err != nil || !created {
		t.Fatalf("create = %v, %v", created, err)
	}
	created, err = store.Put("pages/test.html", []byte("first"), true)
	if err != nil || created {
		t.Fatalf("idempotent create = %v, %v", created, err)
	}
	if _, err := store.Put("pages/test.html", []byte("conflict"), true); !errors.Is(err, errContentConflict) {
		t.Fatalf("create conflict = %v", err)
	}
	if _, err := store.Put("pages/test.html", []byte("second"), false); err != nil {
		t.Fatal(err)
	}
	object, err := store.Get("pages/test.html")
	if err != nil || string(object.Body) != "second" || object.LastModified.IsZero() {
		t.Fatalf("get = %#v, %v", object, err)
	}
	if err := store.Delete("pages/test.html"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("pages/test.html"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted get = %v", err)
	}
}
