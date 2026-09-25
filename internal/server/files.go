package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/protocol"
)

const (
	defaultMaxFileBytes int64 = 100 << 20
	fileMetadataVersion       = 1
	maxFileNameBytes          = 255
	// fileTransferTimeout replaces the server's short read and write timeouts
	// once a file upload is authenticated or a download begins.
	fileTransferTimeout = 30 * time.Minute
)

// errObjectTooLarge reports that the storage backend refused an object for
// its size, which can be lower than PAGEUP_MAX_FILE_BYTES.
var errObjectTooLarge = errors.New("object exceeds the storage size limit")

type fileMetadata struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	OwnerKeyID  string    `json:"owner_key_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Blob        string    `json:"blob"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Revision    uint64    `json:"revision"`
}

// spooledUpload is an authenticated request body that matched its signed hash,
// held in a temporary file until it reaches storage.
type spooledUpload struct {
	file   *os.File
	size   int64
	sha256 string
}

func (upload spooledUpload) discard() {
	upload.file.Close()
	os.Remove(upload.file.Name())
}

// fileContentTypes pins common agent artifacts to stable types; the standard
// library's table depends on the host's mime.types files.
var fileContentTypes = map[string]string{
	".avif":   "image/avif",
	".csv":    "text/csv; charset=utf-8",
	".gif":    "image/gif",
	".gz":     "application/gzip",
	".htm":    "text/html; charset=utf-8",
	".html":   "text/html; charset=utf-8",
	".ico":    "image/x-icon",
	".jpeg":   "image/jpeg",
	".jpg":    "image/jpeg",
	".json":   "application/json",
	".jsonl":  "application/x-ndjson",
	".log":    "text/plain; charset=utf-8",
	".m4a":    "audio/mp4",
	".md":     "text/markdown; charset=utf-8",
	".mov":    "video/quicktime",
	".mp3":    "audio/mpeg",
	".mp4":    "video/mp4",
	".ndjson": "application/x-ndjson",
	".ogg":    "audio/ogg",
	".pdf":    "application/pdf",
	".png":    "image/png",
	".svg":    "image/svg+xml",
	".tar":    "application/x-tar",
	".tgz":    "application/gzip",
	".tsv":    "text/tab-separated-values; charset=utf-8",
	".txt":    "text/plain; charset=utf-8",
	".wav":    "audio/wav",
	".webm":   "video/webm",
	".webp":   "image/webp",
	".yaml":   "application/yaml",
	".yml":    "application/yaml",
	".zip":    "application/zip",
}

func (server *Server) handleFileAPI(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(strings.TrimPrefix(request.URL.EscapedPath(), "/api/files/"), "/")
	switch request.Method {
	case http.MethodPost:
		if len(segments) != 1 {
			http.NotFound(writer, request)
			return
		}
		name, ok := parseFileName(segments[0])
		if !ok {
			writeError(writer, http.StatusBadRequest, "invalid file name")
			return
		}
		server.handleFileCreate(writer, request, name)
	case http.MethodPut:
		if len(segments) > 2 || !protocol.IsUUIDv7(segments[0]) {
			http.NotFound(writer, request)
			return
		}
		name := ""
		if len(segments) == 2 {
			var ok bool
			if name, ok = parseFileName(segments[1]); !ok {
				writeError(writer, http.StatusBadRequest, "invalid file name")
				return
			}
		}
		server.handleFileUpdate(writer, request, segments[0], name)
	case http.MethodDelete:
		if len(segments) != 1 || !protocol.IsUUIDv7(segments[0]) {
			http.NotFound(writer, request)
			return
		}
		server.handleFileDelete(writer, request, segments[0])
	default:
		writer.Header().Set("Allow", "POST, PUT, DELETE")
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (server *Server) handleFileCreate(writer http.ResponseWriter, request *http.Request, name string) {
	key, nonce, declared, ok := server.authorizeFileUpload(writer, request)
	if !ok {
		return
	}
	upload, ok := server.spoolUpload(writer, request, declared)
	if !ok {
		return
	}
	defer upload.discard()

	now := server.config.Now().UTC()
	metadata := fileMetadata{
		Version:     fileMetadataVersion,
		ID:          nonce,
		OwnerKeyID:  key.ID,
		Name:        name,
		ContentType: detectFileContentType(name, upload.file),
		Size:        upload.size,
		SHA256:      upload.sha256,
		Blob:        nonce,
		CreatedAt:   now,
		UpdatedAt:   now,
		Revision:    1,
	}
	if !server.storeFileBlob(writer, request, metadata, upload) {
		return
	}
	created, err := server.writeFileMetadata(metadata, true)
	if err != nil || !created {
		server.store.Delete(fileBlobKey(metadata.ID, metadata.Blob))
		if err == nil || errors.Is(err, errContentConflict) {
			writeError(writer, http.StatusConflict, "file id already exists")
			return
		}
		server.config.Logger.Error("write file metadata", "file_id", metadata.ID, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not store file")
		return
	}
	response := server.fileResponse(request, metadata)
	response.Created = true
	writeJSON(writer, http.StatusCreated, response)
}

func (server *Server) handleFileUpdate(writer http.ResponseWriter, request *http.Request, id, name string) {
	key, nonce, declared, ok := server.authorizeFileUpload(writer, request)
	if !ok {
		return
	}
	current, err := server.readFileMetadata(id)
	if !server.allowFileChange(writer, id, key, current, err) {
		return
	}
	if name == "" {
		name = current.Name
	}
	if declared == current.SHA256 && name == current.Name {
		writeJSON(writer, http.StatusOK, server.fileResponse(request, current))
		return
	}
	upload, ok := server.spoolUpload(writer, request, declared)
	if !ok {
		return
	}
	defer upload.discard()

	replacement := fileMetadata{
		ID:          id,
		Name:        name,
		ContentType: detectFileContentType(name, upload.file),
		Size:        upload.size,
		SHA256:      upload.sha256,
		Blob:        nonce,
	}
	if !server.storeFileBlob(writer, request, replacement, upload) {
		return
	}
	newBlobKey := fileBlobKey(id, nonce)

	server.files.Lock()
	previous, err := server.readFileMetadata(id)
	if !server.allowFileChange(writer, id, key, previous, err) {
		server.files.Unlock()
		server.store.Delete(newBlobKey)
		return
	}
	updated := previous
	updated.Name = replacement.Name
	updated.ContentType = replacement.ContentType
	updated.Size = replacement.Size
	updated.SHA256 = replacement.SHA256
	updated.Blob = replacement.Blob
	updated.UpdatedAt = server.config.Now().UTC()
	updated.Revision++
	_, err = server.writeFileMetadata(updated, false)
	server.files.Unlock()
	if err != nil {
		server.store.Delete(newBlobKey)
		server.config.Logger.Error("write file metadata", "file_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not update file")
		return
	}
	if err := server.store.Delete(fileBlobKey(id, previous.Blob)); err != nil {
		server.config.Logger.Warn("remove replaced file content", "file_id", id, "error", err)
	}
	response := server.fileResponse(request, updated)
	response.Updated = true
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) handleFileDelete(writer http.ResponseWriter, request *http.Request, id string) {
	key, _, ok := server.authorize(writer, request, nil, false)
	if !ok {
		return
	}
	server.files.Lock()
	metadata, err := server.readFileMetadata(id)
	if !server.allowFileChange(writer, id, key, metadata, err) {
		server.files.Unlock()
		return
	}
	err = server.store.Delete(fileMetadataKey(id))
	server.files.Unlock()
	if err != nil {
		server.config.Logger.Error("delete file metadata", "file_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not delete file")
		return
	}
	if err := server.store.Delete(fileBlobKey(id, metadata.Blob)); err != nil {
		server.config.Logger.Warn("remove deleted file content", "file_id", id, "error", err)
	}
	response := server.fileResponse(request, metadata)
	response.Deleted = true
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) handleFile(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	id, segment, hasName := strings.Cut(strings.TrimPrefix(request.URL.EscapedPath(), "/f/"), "/")
	if !protocol.IsUUIDv7(id) {
		http.NotFound(writer, request)
		return
	}
	metadata, err := server.readFileMetadata(id)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.config.Logger.Error("read file metadata", "file_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not read file")
		return
	}
	if name, err := url.PathUnescape(segment); !hasName || err != nil || name != metadata.Name {
		location := "/f/" + id + "/" + url.PathEscape(metadata.Name)
		if request.URL.RawQuery != "" {
			location += "?" + request.URL.RawQuery
		}
		http.Redirect(writer, request, location, http.StatusTemporaryRedirect)
		return
	}
	content, err := server.store.OpenStream(request.Context(), fileBlobKey(id, metadata.Blob), metadata.Size)
	if errors.Is(err, os.ErrNotExist) {
		// An update may have replaced the content after metadata was read.
		metadata, err = server.readFileMetadata(id)
		if err == nil {
			content, err = server.store.OpenStream(request.Context(), fileBlobKey(id, metadata.Blob), metadata.Size)
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.config.Logger.Error("open file content", "file_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not read file")
		return
	}
	defer content.Close()

	disposition := "attachment"
	if inlineFileType(metadata.ContentType) && !request.URL.Query().Has("download") {
		disposition = "inline"
	}
	if value := mime.FormatMediaType(disposition, map[string]string{"filename": metadata.Name}); value != "" {
		disposition = value
	}
	header := writer.Header()
	header.Set("Content-Type", metadata.ContentType)
	header.Set("Content-Disposition", disposition)
	header.Set("Cache-Control", "no-cache")
	header.Set("ETag", `"`+metadata.SHA256+`"`)
	header.Set("Access-Control-Allow-Origin", "*")
	extendTransferDeadlines(writer)
	http.ServeContent(writer, request, metadata.Name, metadata.UpdatedAt, content)
}

// authorizeFileUpload authenticates a streamed upload from its headers, so an
// unauthorized client cannot make the server read a large body.
func (server *Server) authorizeFileUpload(writer http.ResponseWriter, request *http.Request) (api.Key, string, string, bool) {
	declared := request.Header.Get(protocol.HeaderContentSHA256)
	if !validSHA256(declared) {
		writeError(writer, http.StatusBadRequest, protocol.HeaderContentSHA256+" must be a lowercase hex SHA-256 digest")
		return api.Key{}, "", "", false
	}
	if request.ContentLength < 0 {
		writeError(writer, http.StatusLengthRequired, "file uploads require Content-Length")
		return api.Key{}, "", "", false
	}
	if request.ContentLength > server.config.MaxFileBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "file exceeds the "+formatByteSize(server.config.MaxFileBytes)+" upload limit")
		return api.Key{}, "", "", false
	}
	key, nonce, ok := server.authorizeHash(writer, request, declared, false)
	return key, nonce, declared, ok
}

// spoolUpload copies the request body to a temporary file while hashing it and
// rejects a body that differs from the signed hash.
func (server *Server) spoolUpload(writer http.ResponseWriter, request *http.Request, declared string) (spooledUpload, bool) {
	extendTransferDeadlines(writer)
	temporary, err := os.CreateTemp("", "pageup-upload-*")
	if err != nil {
		server.config.Logger.Error("create upload file", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not store file")
		return spooledUpload{}, false
	}
	upload := spooledUpload{file: temporary}
	hash := sha256.New()
	body := http.MaxBytesReader(writer, request.Body, server.config.MaxFileBytes)
	upload.size, err = io.Copy(io.MultiWriter(temporary, hash), body)
	if err != nil {
		upload.discard()
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(writer, http.StatusRequestEntityTooLarge, "file exceeds the "+formatByteSize(server.config.MaxFileBytes)+" upload limit")
		} else {
			writeError(writer, http.StatusBadRequest, "could not read request body")
		}
		return spooledUpload{}, false
	}
	upload.sha256 = hex.EncodeToString(hash.Sum(nil))
	if upload.size != request.ContentLength || upload.sha256 != declared {
		upload.discard()
		writeError(writer, http.StatusBadRequest, "file body does not match its signed SHA-256")
		return spooledUpload{}, false
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		upload.discard()
		server.config.Logger.Error("rewind upload file", "error", err)
		writeError(writer, http.StatusInternalServerError, "could not store file")
		return spooledUpload{}, false
	}
	return upload, true
}

func (server *Server) storeFileBlob(writer http.ResponseWriter, request *http.Request, metadata fileMetadata, upload spooledUpload) bool {
	err := server.store.PutStream(request.Context(), fileBlobKey(metadata.ID, metadata.Blob), upload.file, upload.size, metadata.ContentType)
	if err == nil {
		return true
	}
	if errors.Is(err, errObjectTooLarge) {
		writeError(writer, http.StatusRequestEntityTooLarge, "file exceeds the storage backend's size limit")
		return false
	}
	server.config.Logger.Error("store file content", "file_id", metadata.ID, "error", err)
	writeError(writer, http.StatusInternalServerError, "could not store file")
	return false
}

// allowFileChange writes the HTTP error for a failed metadata lookup or a key
// that neither owns the file nor has the admin role.
func (server *Server) allowFileChange(writer http.ResponseWriter, id string, key api.Key, metadata fileMetadata, err error) bool {
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeError(writer, http.StatusNotFound, "file not found")
	case err != nil:
		server.config.Logger.Error("read file metadata", "file_id", id, "error", err)
		writeError(writer, http.StatusInternalServerError, "could not read file")
	case metadata.OwnerKeyID != key.ID && key.Role != RoleAdmin:
		writeError(writer, http.StatusForbidden, "this key cannot change that file")
	default:
		return true
	}
	return false
}

func (server *Server) readFileMetadata(id string) (fileMetadata, error) {
	object, err := server.store.Get(fileMetadataKey(id))
	if err != nil {
		return fileMetadata{}, err
	}
	var metadata fileMetadata
	if err := json.Unmarshal(object.Body, &metadata); err != nil {
		return fileMetadata{}, fmt.Errorf("parse file metadata: %w", err)
	}
	if metadata.Version != fileMetadataVersion || metadata.ID != id || metadata.OwnerKeyID == "" || !validFileName(metadata.Name) ||
		metadata.ContentType == "" || metadata.Size < 0 || !validSHA256(metadata.SHA256) || !protocol.IsUUIDv7(metadata.Blob) ||
		metadata.CreatedAt.IsZero() || metadata.UpdatedAt.IsZero() || metadata.Revision == 0 {
		return fileMetadata{}, errors.New("invalid file metadata")
	}
	return metadata, nil
}

func (server *Server) writeFileMetadata(metadata fileMetadata, createOnly bool) (bool, error) {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return false, err
	}
	return server.store.Put(fileMetadataKey(metadata.ID), append(data, '\n'), createOnly)
}

func (server *Server) fileResponse(request *http.Request, metadata fileMetadata) api.FileResponse {
	return api.FileResponse{
		ID:          metadata.ID,
		URL:         server.publicURL(request) + "/f/" + metadata.ID + "/" + url.PathEscape(metadata.Name),
		Name:        metadata.Name,
		ContentType: metadata.ContentType,
		Size:        metadata.Size,
		SHA256:      metadata.SHA256,
		Revision:    metadata.Revision,
	}
}

func fileMetadataKey(id string) string {
	return "files/" + id + ".json"
}

// fileBlobKey stores each revision's content under its own key, so a reader
// holding older metadata never streams a partially replaced file.
func fileBlobKey(id, blob string) string {
	return "files/" + id + "." + blob + ".blob"
}

func parseFileName(segment string) (string, bool) {
	name, err := url.PathUnescape(segment)
	if err != nil || !validFileName(name) {
		return "", false
	}
	return name, true
}

func validFileName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxFileNameBytes || !utf8.ValidString(name) {
		return false
	}
	for _, character := range name {
		if character == '/' || character == '\\' || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func detectFileContentType(name string, content io.ReaderAt) string {
	extension := strings.ToLower(path.Ext(name))
	if contentType, ok := fileContentTypes[extension]; ok {
		return contentType
	}
	if contentType := mime.TypeByExtension(extension); contentType != "" {
		return contentType
	}
	head := make([]byte, 512)
	count, _ := content.ReadAt(head, 0)
	return http.DetectContentType(head[:count])
}

// inlineFileType reports whether browsers may render a hosted file in place.
// Types that can run script, such as HTML and SVG, always download.
func inlineFileType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch mediaType {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon",
		"application/pdf", "application/json", "application/x-ndjson",
		"text/plain", "text/markdown", "text/csv", "text/tab-separated-values":
		return true
	}
	return strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/")
}

// extendTransferDeadlines lifts the server-wide read and write timeouts for a
// file transfer. Connections without deadline support are left unchanged.
func extendTransferDeadlines(writer http.ResponseWriter) {
	controller := http.NewResponseController(writer)
	deadline := time.Now().Add(fileTransferTimeout)
	controller.SetReadDeadline(deadline)
	controller.SetWriteDeadline(deadline)
}

func formatByteSize(size int64) string {
	if size%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", size>>20)
	}
	return fmt.Sprintf("%d bytes", size)
}
