package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const redactedPlaceholder = "***REDACTED***"

var (
	memKey     [32]byte
	memKeyOnce sync.Once
)

func initMemKey() {
	if _, err := io.ReadFull(rand.Reader, memKey[:]); err != nil {
		panic("failed to generate in-memory encryption key: " + err.Error())
	}
}

func newGCM() (cipher.AEAD, error) {
	memKeyOnce.Do(initMemKey)
	block, err := aes.NewCipher(memKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encrypt(plain []byte) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

type SecretString struct {
	data []byte
}

func NewSecret(s string) SecretString {
	enc, err := encrypt([]byte(s))
	if err != nil {
		return SecretString{}
	}
	return SecretString{data: enc}
}

func (s SecretString) String() string {
	if len(s.data) == 0 {
		return ""
	}
	return redactedPlaceholder
}

func (s SecretString) GoString() string {
	return redactedPlaceholder
}

func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPlaceholder)
}

func (s *SecretString) UnmarshalJSON(data []byte) error {
	var plain string
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	enc, err := encrypt([]byte(plain))
	if err != nil {
		return err
	}
	s.data = enc
	return nil
}

func (s SecretString) MarshalText() ([]byte, error) {
	return []byte(redactedPlaceholder), nil
}

func (s SecretString) Raw() string {
	plain, err := decrypt(s.data)
	if err != nil {
		return ""
	}
	return string(plain)
}

func (s SecretString) Plain() string {
	plain, err := decrypt(s.data)
	if err != nil {
		return ""
	}
	return string(plain)
}

func (s SecretString) IsSet() bool {
	return len(s.data) > 0
}

func (s SecretString) IsZero() bool {
	return len(s.data) == 0
}

func SanitizeURL(u string) (string, error) {
	if err := ValidateURL(u); err != nil {
		return "", err
	}
	return u, nil
}

func RedactSensitiveData(data string) string {
	if data == "" {
		return data
	}
	return redactedPlaceholder
}

func ClearSensitiveData(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func SanitizeForCommand(s string) string {
	return SanitizeInput(s)
}

func (s *SecretString) Zero() {
	for i := range s.data {
		s.data[i] = 0
	}
	s.data = nil
}

func (s SecretString) Len() int {
	data, err := decrypt(s.data)
	if err != nil {
		return 0
	}
	return len(data)
}

type SecretMap map[string]SecretString

type RedactedAPIKey struct {
	Prefix string
	Suffix string
	Length int
}

var sensitiveKeys = []string{
	"api-key", "apikey", "api_key", "authorization", "x-api-key",
	"x-goog-api-key", "secret", "password", "passwd",
	"credential", "bearer",
	"access_key", "secret_key", "private_key",
}

var sensitiveKeySuffixes = []string{
	"_token", "_key", "_secret", "_password",
}

var sensitiveKeyPrefixes = []string{
	"token", "secret",
}

var sensitivePatterns = []struct {
	prefix string
	suffix string
}{
	{"ARES_", "PASSWORD"},
	{"ARES_", "SECRET"},
	{"ARES_", "KEY"},
	{"ARES_", "TOKEN"},
}

var sensitiveJSONPatterns = []string{
	`"(api[-_]?key|token|secret|password|authorization|credential|passwd)"\s*:\s*"[^"]*"`,
	`(Bearer\s+)[A-Za-z0-9\-._~+/]+=*\b`,
	`(x-api-key:\s*)\S+`,
	`(authorization:\s*)\S+`,
	`"([^"]*(?:secret|token|key|password)[^"]*)"\s*[:=]\s*"[^"]*"`,
}
