package web

import (
	"net/http"

	"github.com/ares/engine/internal/auth"
)

type LoginHandler = auth.LoginHandler

func NewLoginHandler(secret string) *LoginHandler {
	return auth.NewLoginHandler(secret)
}

func hashPassword(password string) (string, error) {
	return auth.HashPassword(password)
}

func verifyPassword(password, encoded string) bool {
	return auth.VerifyPassword(password, encoded)
}

func generateSessionToken(username, secret string) (string, error) {
	return auth.GenerateSessionToken(username, secret)
}

func extractToken(r *http.Request) string {
	return auth.ExtractToken(r)
}
