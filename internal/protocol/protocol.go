package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	HeaderKeyID     = "X-Pageup-Key"
	HeaderTimestamp = "X-Pageup-Timestamp"
	HeaderNonce     = "X-Pageup-Nonce"
	HeaderSignature = "X-Pageup-Signature"
	// HeaderContentSHA256 carries the signed body hash for streamed uploads so
	// the server can authenticate a request before reading its body.
	HeaderContentSHA256 = "X-Pageup-Content-SHA256"
	SignaturePrefix     = "pageup-signature-v1"
)

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

func EncodePublicKey(publicKey ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

func EncodePrivateKey(privateKey ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(privateKey)
}

func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := decodeBase64(value)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func DecodePrivateKey(value string) (ed25519.PrivateKey, error) {
	raw, err := decodeBase64(value)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("private key must be %d-byte seed or %d-byte key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func Canonical(method, path string, timestamp int64, nonce string, body []byte) []byte {
	return CanonicalHash(method, path, timestamp, nonce, BodyHash(body))
}

// CanonicalHash builds the same signing input as Canonical from a body hash,
// for streamed bodies whose bytes are not held in memory.
func CanonicalHash(method, path string, timestamp int64, nonce, bodyHash string) []byte {
	return []byte(strings.Join([]string{
		SignaturePrefix,
		strings.ToUpper(method),
		path,
		strconv.FormatInt(timestamp, 10),
		nonce,
		bodyHash,
	}, "\n"))
}

func Sign(privateKey ed25519.PrivateKey, method, path string, timestamp int64, nonce string, body []byte) string {
	return SignHash(privateKey, method, path, timestamp, nonce, BodyHash(body))
}

func SignHash(privateKey ed25519.PrivateKey, method, path string, timestamp int64, nonce, bodyHash string) string {
	signature := ed25519.Sign(privateKey, CanonicalHash(method, path, timestamp, nonce, bodyHash))
	return base64.RawURLEncoding.EncodeToString(signature)
}

func SignRequest(request *http.Request, privateKey ed25519.PrivateKey, nonce string, body []byte, now time.Time) {
	SignRequestHash(request, privateKey, nonce, BodyHash(body), now)
}

func SignRequestHash(request *http.Request, privateKey ed25519.PrivateKey, nonce, bodyHash string, now time.Time) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	timestamp := now.Unix()
	request.Header.Set(HeaderKeyID, KeyID(publicKey))
	request.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature, SignHash(privateKey, request.Method, request.URL.EscapedPath(), timestamp, nonce, bodyHash))
}

func DecodeSignature(value string) ([]byte, error) {
	raw, err := decodeBase64(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature length")
	}
	return raw, nil
}

// NewUUIDv7 returns an RFC 9562 UUIDv7. Its timestamp makes recent uploads sort
// naturally while 74 random bits keep page URLs impractical to guess.
func NewUUIDv7(now time.Time) (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	milliseconds := uint64(now.UnixMilli())
	bytes[0] = byte(milliseconds >> 40)
	bytes[1] = byte(milliseconds >> 32)
	bytes[2] = byte(milliseconds >> 24)
	bytes[3] = byte(milliseconds >> 16)
	bytes[4] = byte(milliseconds >> 8)
	bytes[5] = byte(milliseconds)
	bytes[6] = (bytes[6] & 0x0f) | 0x70
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

// IsUUIDv7 reports whether value is the canonical lowercase representation of
// an RFC 9562 UUIDv7.
func IsUUIDv7(value string) bool {
	return uuidV7Pattern.MatchString(value)
}
