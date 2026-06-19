package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	IssuerURL           string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	AllowedRedirectURIs []string
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type OIDCProvider struct {
	cfg      OIDCConfig
	oauthCfg *oauth2.Config
	stateMu  sync.Mutex
	states   map[string]time.Time
	jwksMu   sync.RWMutex
	jwks     map[string]*rsa.PublicKey
	jwksURL  string
}

func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.Scopes == nil {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	if len(cfg.AllowedRedirectURIs) > 0 {
		allowed := false
		for _, uri := range cfg.AllowedRedirectURIs {
			if uri == cfg.RedirectURL {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("redirect URL %s not in allowed list", cfg.RedirectURL)
		}
	}

	endpoint := oauth2.Endpoint{
		AuthURL:  cfg.IssuerURL + "/authorize",
		TokenURL: cfg.IssuerURL + "/token",
	}

	if strings.Contains(cfg.IssuerURL, "accounts.google.com") {
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		}
	} else if strings.Contains(cfg.IssuerURL, "login.microsoftonline.com") || strings.Contains(cfg.IssuerURL, "login.windows.net") {
		endpoint = oauth2.Endpoint{
			AuthURL:  cfg.IssuerURL + "/oauth2/v2.0/authorize",
			TokenURL: cfg.IssuerURL + "/oauth2/v2.0/token",
		}
	}

	return &OIDCProvider{
		cfg: cfg,
		oauthCfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     endpoint,
		},
		states:  make(map[string]time.Time),
		jwks:    make(map[string]*rsa.PublicKey),
		jwksURL: cfg.IssuerURL + "/.well-known/jwks.json",
	}, nil
}

func (p *OIDCProvider) AuthURL() (string, string, error) {
	state, err := generateState()
	if err != nil {
		return "", "", err
	}

	p.stateMu.Lock()
	p.states[state] = time.Now().Add(10 * time.Minute)
	p.stateMu.Unlock()

	url := p.oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
	return url, state, nil
}

func (p *OIDCProvider) HandleCallback(code, state string) (*OIDCUserInfo, error) {
	p.stateMu.Lock()
	expires, ok := p.states[state]
	if !ok || time.Now().After(expires) {
		p.stateMu.Unlock()
		return nil, fmt.Errorf("invalid or expired state")
	}
	delete(p.states, state)
	p.stateMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := p.oauthCfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}

	if err := p.verifyIDToken(idToken); err != nil {
		return nil, fmt.Errorf("id_token validation failed: %w", err)
	}

	userInfo, err := p.fetchUserInfo(token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("user info fetch failed: %w", err)
	}

	return userInfo, nil
}

func (p *OIDCProvider) verifyIDToken(idToken string) error {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid id_token format")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode id_token header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fmt.Errorf("failed to parse id_token header: %w", err)
	}

	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported id_token algorithm: %s", header.Alg)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode id_token payload: %w", err)
	}

	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	if claims.Iss != p.cfg.IssuerURL && !strings.HasPrefix(claims.Iss, p.cfg.IssuerURL) {
		return fmt.Errorf("id_token issuer mismatch: got %s, expected %s", claims.Iss, p.cfg.IssuerURL)
	}

	if claims.Aud != p.cfg.ClientID {
		return fmt.Errorf("id_token audience mismatch: got %s, expected %s", claims.Aud, p.cfg.ClientID)
	}

	if time.Now().Unix() > claims.Exp {
		return fmt.Errorf("id_token has expired")
	}

	pubKey, err := p.getJWKSPublicKey(header.Kid)
	if err != nil {
		return fmt.Errorf("failed to get JWKS public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode id_token signature: %w", err)
	}

	msg := []byte(parts[0] + "." + parts[1])
	chash := sha256.Sum256(msg)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, chash[:], sig); err != nil {
		return fmt.Errorf("id_token signature verification failed: %w", err)
	}

	return nil
}

func (p *OIDCProvider) getJWKSPublicKey(kid string) (*rsa.PublicKey, error) {
	p.jwksMu.RLock()
	key, ok := p.jwks[kid]
	p.jwksMu.RUnlock()
	if ok {
		return key, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.jwksURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	p.jwksMu.Lock()
	defer p.jwksMu.Unlock()

	for _, k := range jwks.Keys {
		if k.Use != "sig" {
			continue
		}
		pk, err := jwkToPublicKey(&k)
		if err != nil {
			continue
		}
		p.jwks[k.Kid] = pk
	}

	key, ok = p.jwks[kid]
	if !ok {
		return nil, fmt.Errorf("no JWK found for kid: %s", kid)
	}
	return key, nil
}

func jwkToPublicKey(jwk *jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func (p *OIDCProvider) fetchUserInfo(accessToken string) (*OIDCUserInfo, error) {
	userInfoURL := p.cfg.IssuerURL + "/userinfo"

	if strings.Contains(p.cfg.IssuerURL, "accounts.google.com") {
		userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	} else if strings.Contains(p.cfg.IssuerURL, "login.microsoftonline.com") || strings.Contains(p.cfg.IssuerURL, "login.windows.net") {
		userInfoURL = "https://graph.microsoft.com/oidc/userinfo"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			MaxConnsPerHost: 5,
			IdleConnTimeout: 90 * time.Second,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	var userInfo OIDCUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

type OIDCUserInfo struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	Picture       string   `json:"picture"`
	Groups        []string `json:"groups,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

func (u *OIDCUserInfo) MapToRole(defaultRole UserRole) UserRole {
	for _, role := range u.Roles {
		switch strings.ToLower(role) {
		case "admin", "administrator":
			return RoleAdmin
		case "operator", "editor":
			return RoleOperator
		case "viewer", "reader":
			return RoleViewer
		}
	}

	for _, group := range u.Groups {
		lower := strings.ToLower(group)
		if strings.Contains(lower, "admin") {
			return RoleAdmin
		}
		if strings.Contains(lower, "operator") || strings.Contains(lower, "security") {
			return RoleOperator
		}
	}

	return defaultRole
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
