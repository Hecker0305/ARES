package authflow

import (
	"testing"
)

func TestNewAuthFlow(t *testing.T) {
	a := AuthFlow{TargetURL: "http://example.com"}
	if a.TargetURL != "http://example.com" {
		t.Errorf("expected http://example.com, got %s", a.TargetURL)
	}
}

func TestCSRFToken(t *testing.T) {
	csrf := CSRFToken{
		ParameterName: "csrf_token",
		HeaderName:    "X-CSRF-Token",
		Endpoint:      "/csrf",
		CookieName:    "csrf_cookie",
	}
	if csrf.ParameterName != "csrf_token" {
		t.Errorf("expected csrf_token, got %s", csrf.ParameterName)
	}
}

func TestOAuthFlow(t *testing.T) {
	oauth := OAuthFlow{
		Type:     "authorization_code",
		AuthURL:  "https://provider.com/auth",
		TokenURL: "https://provider.com/token",
		Scopes:   []string{"openid", "profile"},
	}
	if oauth.Type != "authorization_code" {
		t.Errorf("expected authorization_code, got %s", oauth.Type)
	}
}

func TestJWTConfig(t *testing.T) {
	jwt := JWTConfig{
		Algorithm: "RS256",
	}
	if jwt.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", jwt.Algorithm)
	}
}
