package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/desarso/pageup/internal/api"
	"github.com/desarso/pageup/internal/protocol"
)

const (
	RoleAdmin  = "admin"
	RoleUpload = "upload"
)

type keyFile struct {
	Version int       `json:"version"`
	Keys    []api.Key `json:"keys"`
}

type KeyStore struct {
	mu    sync.RWMutex
	store objectStore
	key   string
	keys  map[string]api.Key
}

func NewKeyStore(path string, bootstrapJSON string, now time.Time) (*KeyStore, error) {
	storage, err := newFilesystemObjectStore(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return newKeyStore(storage, filepath.Base(path), bootstrapJSON, now)
}

func newKeyStore(storage objectStore, key, bootstrapJSON string, now time.Time) (*KeyStore, error) {
	store := &KeyStore{store: storage, key: key, keys: make(map[string]api.Key)}
	object, err := storage.Get(key)
	if err == nil {
		if err := store.load(object.Body); err != nil {
			return nil, fmt.Errorf("load key store: %w", err)
		}
		return store, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key store: %w", err)
	}

	if strings.TrimSpace(bootstrapJSON) == "" {
		return nil, errors.New("no key store exists and PAGEUP_BOOTSTRAP_KEYS is empty")
	}
	var bootstrap []api.Key
	if err := json.Unmarshal([]byte(bootstrapJSON), &bootstrap); err != nil {
		return nil, fmt.Errorf("parse PAGEUP_BOOTSTRAP_KEYS: %w", err)
	}
	if len(bootstrap) == 0 {
		return nil, errors.New("PAGEUP_BOOTSTRAP_KEYS must contain at least one key")
	}
	for _, key := range bootstrap {
		publicKey, err := protocol.DecodePublicKey(key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("bootstrap key %q: %w", key.Name, err)
		}
		key.ID = protocol.KeyID(publicKey)
		key.PublicKey = protocol.EncodePublicKey(publicKey)
		key.Name = strings.TrimSpace(key.Name)
		if key.Name == "" {
			return nil, errors.New("bootstrap key name cannot be empty")
		}
		if key.Role == "" {
			key.Role = RoleAdmin
		}
		if !validRole(key.Role) {
			return nil, fmt.Errorf("bootstrap key %q has invalid role %q", key.Name, key.Role)
		}
		if key.CreatedAt.IsZero() {
			key.CreatedAt = now.UTC()
		}
		store.keys[key.ID] = key
	}
	if store.adminCountLocked() == 0 {
		return nil, errors.New("PAGEUP_BOOTSTRAP_KEYS must contain at least one admin key")
	}
	if err := store.saveLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *KeyStore) load(data []byte) error {
	var file keyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	if file.Version != 1 {
		return fmt.Errorf("unsupported key store version %d", file.Version)
	}
	for _, key := range file.Keys {
		publicKey, err := protocol.DecodePublicKey(key.PublicKey)
		if err != nil {
			return fmt.Errorf("key %q: %w", key.Name, err)
		}
		if key.ID != protocol.KeyID(publicKey) {
			return fmt.Errorf("key %q has mismatched id", key.Name)
		}
		if !validRole(key.Role) {
			return fmt.Errorf("key %q has invalid role", key.Name)
		}
		store.keys[key.ID] = key
	}
	if store.adminCountLocked() == 0 {
		return errors.New("key store contains no admin key")
	}
	return nil
}

func validRole(role string) bool {
	return role == RoleAdmin || role == RoleUpload
}

func (store *KeyStore) Get(id string) (api.Key, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	key, ok := store.keys[id]
	return key, ok
}

func (store *KeyStore) PublicKey(id string) (ed25519.PublicKey, api.Key, bool) {
	key, ok := store.Get(id)
	if !ok {
		return nil, api.Key{}, false
	}
	publicKey, err := protocol.DecodePublicKey(key.PublicKey)
	if err != nil {
		return nil, api.Key{}, false
	}
	return publicKey, key, true
}

func (store *KeyStore) List() []api.Key {
	store.mu.RLock()
	defer store.mu.RUnlock()
	keys := make([]api.Key, 0, len(store.keys))
	for _, key := range store.keys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].Name < keys[j].Name
		}
		return keys[i].CreatedAt.Before(keys[j].CreatedAt)
	})
	return keys
}

func (store *KeyStore) Add(name string, publicKey ed25519.PublicKey, role string, now time.Time) (api.Key, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return api.Key{}, false, errors.New("key name cannot be empty")
	}
	if len(name) > 80 {
		return api.Key{}, false, errors.New("key name is too long")
	}
	if !validRole(role) {
		return api.Key{}, false, errors.New("role must be admin or upload")
	}
	key := api.Key{
		ID:        protocol.KeyID(publicKey),
		Name:      name,
		PublicKey: protocol.EncodePublicKey(publicKey),
		Role:      role,
		CreatedAt: now.UTC(),
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.keys[key.ID]; ok {
		return existing, false, nil
	}
	store.keys[key.ID] = key
	if err := store.saveLocked(); err != nil {
		delete(store.keys, key.ID)
		return api.Key{}, false, err
	}
	return key, true, nil
}

func (store *KeyStore) Remove(id string) (api.Key, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key, ok := store.keys[id]
	if !ok {
		return api.Key{}, os.ErrNotExist
	}
	if key.Role == RoleAdmin && store.adminCountLocked() <= 1 {
		return api.Key{}, errors.New("cannot remove the last admin key")
	}
	delete(store.keys, id)
	if err := store.saveLocked(); err != nil {
		store.keys[id] = key
		return api.Key{}, err
	}
	return key, nil
}

func (store *KeyStore) adminCountLocked() int {
	count := 0
	for _, key := range store.keys {
		if key.Role == RoleAdmin {
			count++
		}
	}
	return count
}

func (store *KeyStore) saveLocked() error {
	keys := make([]api.Key, 0, len(store.keys))
	for _, key := range store.keys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	data, err := json.MarshalIndent(keyFile{Version: 1, Keys: keys}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := store.store.Put(store.key, data, false); err != nil {
		return fmt.Errorf("replace key store: %w", err)
	}
	return nil
}
