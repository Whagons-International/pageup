package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/desarso/pageup/internal/protocol"
)

const DefaultEndpoint = "https://pageup.whagons.com"

type Config struct {
	Version    int    `json:"version"`
	Endpoint   string `json:"endpoint"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name,omitempty"`
}

func DefaultConfigPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv("PAGEUP_CONFIG")); path != "" {
		return path, nil
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "pageup", "config.json"), nil
}

func GenerateConfig(endpoint, name string) (Config, error) {
	endpoint, err := validateEndpoint(endpoint)
	if err != nil {
		return Config{}, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Config{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return Config{
		Version:    1,
		Endpoint:   endpoint,
		KeyID:      protocol.KeyID(publicKey),
		PrivateKey: protocol.EncodePrivateKey(privateKey),
		Name:       strings.TrimSpace(name),
	}, nil
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return Config{}, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			privateKeyValue := strings.TrimSpace(os.Getenv("PAGEUP_PRIVATE_KEY"))
			if privateKeyValue == "" {
				return Config{}, fmt.Errorf("no pageup credentials at %s; run 'pageup auth login'", path)
			}
			privateKey, decodeErr := protocol.DecodePrivateKey(privateKeyValue)
			if decodeErr != nil {
				return Config{}, decodeErr
			}
			endpoint := strings.TrimSpace(os.Getenv("PAGEUP_ENDPOINT"))
			if endpoint == "" {
				endpoint = DefaultEndpoint
			}
			config := Config{
				Version:    1,
				Endpoint:   endpoint,
				KeyID:      protocol.KeyID(privateKey.Public().(ed25519.PublicKey)),
				PrivateKey: privateKeyValue,
				Name:       strings.TrimSpace(os.Getenv("PAGEUP_DEVICE_NAME")),
			}
			if err := config.Validate(); err != nil {
				return Config{}, fmt.Errorf("invalid environment credentials: %w", err)
			}
			return config, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if endpoint := strings.TrimSpace(os.Getenv("PAGEUP_ENDPOINT")); endpoint != "" {
		config.Endpoint = endpoint
	}
	if privateKey := strings.TrimSpace(os.Getenv("PAGEUP_PRIVATE_KEY")); privateKey != "" {
		config.PrivateKey = privateKey
		decoded, decodeErr := protocol.DecodePrivateKey(privateKey)
		if decodeErr != nil {
			return Config{}, decodeErr
		}
		config.KeyID = protocol.KeyID(decoded.Public().(ed25519.PublicKey))
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	return config, nil
}

func SaveConfig(path string, config Config, force bool) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config already exists at %s (use --force to replace it)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	return os.Chmod(path, 0o600)
}

func (config Config) Validate() error {
	if config.Version != 1 {
		return fmt.Errorf("unsupported config version %d", config.Version)
	}
	endpoint, err := validateEndpoint(config.Endpoint)
	if err != nil {
		return err
	}
	config.Endpoint = endpoint
	privateKey, err := protocol.DecodePrivateKey(config.PrivateKey)
	if err != nil {
		return err
	}
	actualKeyID := protocol.KeyID(privateKey.Public().(ed25519.PublicKey))
	if config.KeyID != "" && config.KeyID != actualKeyID {
		return errors.New("key_id does not match private_key")
	}
	return nil
}

func (config Config) Private() (ed25519.PrivateKey, error) {
	return protocol.DecodePrivateKey(config.PrivateKey)
}

func (config Config) PublicKey() (ed25519.PublicKey, error) {
	privateKey, err := config.Private()
	if err != nil {
		return nil, err
	}
	return privateKey.Public().(ed25519.PublicKey), nil
}

func validateEndpoint(value string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("endpoint must be an origin such as https://pages.example.com")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", errors.New("endpoint scheme must be https or http")
	}
	return value, nil
}
