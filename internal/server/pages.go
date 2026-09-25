package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/desarso/pageup/internal/api"
)

const pageMetadataVersion = 1

var errPageForbidden = errors.New("page update forbidden")

type pageKind string

const (
	pageKindHTML pageKind = "html"
	pageKindSite pageKind = "site"
)

type pageMetadata struct {
	Version    int       `json:"version"`
	ID         string    `json:"id"`
	OwnerKeyID string    `json:"owner_key_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Revision   uint64    `json:"revision"`
}

func (server *Server) createPage(id string, key api.Key, kind pageKind, body []byte) (bool, pageMetadata, error) {
	server.pages.Lock()
	defer server.pages.Unlock()

	metadataKey := server.pageMetadataKey(id)
	existingKind, _, existing, err := server.readPageContent(id)
	if err == nil {
		if existingKind != kind || !bytes.Equal(existing.Body, body) {
			return false, pageMetadata{}, errContentConflict
		}
		metadata, err := readPageMetadataFromStore(server.store, metadataKey, id)
		if errors.Is(err, os.ErrNotExist) {
			if key.Role != RoleAdmin {
				return false, pageMetadata{}, errContentConflict
			}
			metadata = newPageMetadata(id, key.ID, existing.LastModified)
			if err := writePageMetadataToStore(server.store, metadataKey, metadata); err != nil {
				return false, pageMetadata{}, err
			}
			return false, metadata, nil
		}
		if err != nil {
			return false, pageMetadata{}, err
		}
		if metadata.OwnerKeyID != key.ID && key.Role != RoleAdmin {
			return false, pageMetadata{}, errContentConflict
		}
		return false, metadata, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, pageMetadata{}, err
	}

	contentKey := server.pageContentKey(id, kind)
	created, err := server.store.Put(contentKey, body, true)
	if err != nil {
		return false, pageMetadata{}, err
	}
	if !created {
		return false, pageMetadata{}, errContentConflict
	}

	metadata := newPageMetadata(id, key.ID, server.config.Now())
	if err := writePageMetadataToStore(server.store, metadataKey, metadata); err != nil {
		if removeErr := server.store.Delete(contentKey); removeErr != nil {
			return false, pageMetadata{}, fmt.Errorf("write metadata: %w (remove incomplete page: %v)", err, removeErr)
		}
		return false, pageMetadata{}, fmt.Errorf("write metadata: %w", err)
	}
	return true, metadata, nil
}

func (server *Server) updatePage(id string, key api.Key, kind pageKind, body []byte) (bool, pageMetadata, error) {
	server.pages.Lock()
	defer server.pages.Unlock()

	existingKind, existingKey, existing, err := server.readPageContent(id)
	if err != nil {
		return false, pageMetadata{}, err
	}
	metadataKey := server.pageMetadataKey(id)

	metadataMissing := false
	metadata, err := readPageMetadataFromStore(server.store, metadataKey, id)
	if errors.Is(err, os.ErrNotExist) {
		if key.Role != RoleAdmin {
			return false, pageMetadata{}, errPageForbidden
		}
		metadataMissing = true
		metadata = newPageMetadata(id, key.ID, existing.LastModified)
	} else if err != nil {
		return false, pageMetadata{}, err
	} else if metadata.OwnerKeyID != key.ID && key.Role != RoleAdmin {
		return false, pageMetadata{}, errPageForbidden
	}

	if existingKind == kind && bytes.Equal(existing.Body, body) {
		if metadataMissing {
			if err := writePageMetadataToStore(server.store, metadataKey, metadata); err != nil {
				return false, pageMetadata{}, err
			}
		}
		return false, metadata, nil
	}

	updated := metadata
	updated.Revision++
	updated.UpdatedAt = server.config.Now().UTC()
	targetKey := server.pageContentKey(id, kind)
	if existingKind != kind {
		if _, err := server.store.Get(targetKey); err == nil {
			return false, pageMetadata{}, errors.New("page has conflicting stored content")
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, pageMetadata{}, err
		}
	}
	if _, err := server.store.Put(targetKey, body, false); err != nil {
		return false, pageMetadata{}, err
	}
	if existingKind != kind {
		if err := server.store.Delete(existingKey); err != nil {
			server.store.Delete(targetKey)
			return false, pageMetadata{}, err
		}
	}
	if err := writePageMetadataToStore(server.store, metadataKey, updated); err != nil {
		_, rollbackErr := server.store.Put(existingKey, existing.Body, false)
		if existingKind != kind {
			if removeErr := server.store.Delete(targetKey); rollbackErr == nil && removeErr != nil {
				rollbackErr = removeErr
			}
		}
		if rollbackErr != nil {
			return false, pageMetadata{}, fmt.Errorf("write metadata: %w (restore page: %v)", err, rollbackErr)
		}
		return false, pageMetadata{}, fmt.Errorf("write metadata: %w", err)
	}
	return true, updated, nil
}

func (server *Server) pageContentKey(id string, kind pageKind) string {
	extension := ".html"
	if kind == pageKindSite {
		extension = ".site.zip"
	}
	return "pages/" + id + extension
}

func (server *Server) pageMetadataKey(id string) string {
	return "pages/" + id + ".json"
}

func (server *Server) readPageContent(id string) (pageKind, string, storedObject, error) {
	htmlKey := server.pageContentKey(id, pageKindHTML)
	siteKey := server.pageContentKey(id, pageKindSite)
	html, htmlErr := server.store.Get(htmlKey)
	site, siteErr := server.store.Get(siteKey)
	if htmlErr == nil && siteErr == nil {
		return "", "", storedObject{}, errors.New("page has conflicting stored content")
	}
	if htmlErr == nil {
		return pageKindHTML, htmlKey, html, nil
	}
	if siteErr == nil {
		return pageKindSite, siteKey, site, nil
	}
	if !errors.Is(htmlErr, os.ErrNotExist) {
		return "", "", storedObject{}, htmlErr
	}
	if !errors.Is(siteErr, os.ErrNotExist) {
		return "", "", storedObject{}, siteErr
	}
	return "", "", storedObject{}, os.ErrNotExist
}

func newPageMetadata(id, ownerKeyID string, createdAt time.Time) pageMetadata {
	createdAt = createdAt.UTC()
	return pageMetadata{
		Version:    pageMetadataVersion,
		ID:         id,
		OwnerKeyID: ownerKeyID,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Revision:   1,
	}
}

func readPageMetadataFromStore(store objectStore, key, id string) (pageMetadata, error) {
	object, err := store.Get(key)
	if err != nil {
		return pageMetadata{}, err
	}
	return parsePageMetadata(object.Body, id)
}

func readPageMetadata(path, id string) (pageMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pageMetadata{}, err
	}
	return parsePageMetadata(data, id)
}

func parsePageMetadata(data []byte, id string) (pageMetadata, error) {
	var metadata pageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return pageMetadata{}, fmt.Errorf("parse page metadata: %w", err)
	}
	if metadata.Version != pageMetadataVersion || metadata.ID != id || metadata.OwnerKeyID == "" || metadata.CreatedAt.IsZero() || metadata.UpdatedAt.IsZero() || metadata.Revision == 0 {
		return pageMetadata{}, errors.New("invalid page metadata")
	}
	return metadata, nil
}

func writePageMetadataToStore(store objectStore, key string, metadata pageMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = store.Put(key, data, false)
	return err
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	return writeAtomicStream(path, bytes.NewReader(data), mode)
}

func writeAtomicStream(path string, body io.Reader, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".pageup-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
