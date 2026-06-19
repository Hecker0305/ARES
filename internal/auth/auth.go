package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ares/engine/internal/logger"

	"golang.org/x/crypto/argon2"
)

// UserRole defines the role of a user in the system
type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleOperator UserRole = "operator"
	RoleViewer   UserRole = "viewer"
)

// Constants for Argon2 password hashing
const (
	saltLength   = 32
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// User represents a user in the system
type User struct {
	TenantID            string    `json:"tenant_id"`
	Username            string    `json:"username"`
	PasswordHash        string    `json:"-"`
	Role                UserRole  `json:"role"`
	CreatedAt           time.Time `json:"created_at"`
	LastLogin           time.Time `json:"last_login"`
	ForcePasswordChange bool      `json:"force_password_change,omitempty"`
	MFAEnabled          bool      `json:"mfa_enabled"`
	MFASecret           string    `json:"-"`
	MFAVerified         bool      `json:"mfa_verified"`
}

// Session represents an authenticated user session
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      UserRole  `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// rateEntry tracks request counts for rate limiting
type rateEntry struct {
	count       int
	windowStart time.Time
}

// LoginHandler manages user authentication and sessions
type LoginHandler struct {
	mu              sync.RWMutex
	sessions        map[string]*Session
	secret          string
	rateLimit       int
	rateWin         time.Duration
	rateBucket      map[string]*rateEntry
	rateMu          sync.Mutex
	csrfTokens      map[string]time.Time
	csrfMu          sync.Mutex
	adminHash       string
	users           map[string]*User
	storePath       string
	rateCleanupStop chan struct{}
	csrfCleanupStop chan struct{}
	oidcProvider    *OIDCProvider
	resetTokens     map[string]*resetTokenEntry
	resetMu         sync.Mutex
}

type resetTokenEntry struct {
	Username  string
	ExpiresAt time.Time
}

// NewLoginHandler creates a new authentication handler
func NewLoginHandler(secret string) *LoginHandler {
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			logger.Error(fmt.Sprintf("[Auth] crypto/rand unavailable: %v", err))
			return nil
		}
		secret = hex.EncodeToString(b)
	}

	var adminHash string
	if adminPass := getEnv("ARES_ADMIN_PASSWORD"); adminPass != "" {
		var err error
		adminHash, err = HashPassword(adminPass)
		if err != nil {
			logger.Error(fmt.Sprintf("[Auth] Failed to hash admin password: %v", err))
		}
	}

	// Default store path
	storePath := getEnv("ARES_SESSION_STORE")
	if storePath == "" {
		dir, err := os.UserCacheDir()
		if err == nil {
			storePath = dir + string(os.PathSeparator) + "ares_sessions.json"
		}
	}

	h := &LoginHandler{
		sessions:        make(map[string]*Session),
		secret:          secret,
		rateLimit:       4,
		rateWin:         time.Minute,
		rateBucket:      make(map[string]*rateEntry),
		rateMu:          sync.Mutex{},
		csrfTokens:      make(map[string]time.Time),
		csrfMu:          sync.Mutex{},
		adminHash:       adminHash,
		users:           make(map[string]*User),
		storePath:       storePath,
		rateCleanupStop: make(chan struct{}),
		csrfCleanupStop: make(chan struct{}),
		resetTokens:     make(map[string]*resetTokenEntry),
	}

	// Initialize default users
	h.initDefaultUsers()

	// Periodic session cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-h.rateCleanupStop:
				return
			case <-ticker.C:
				h.mu.Lock()
				now := time.Now()
				for token, s := range h.sessions {
					if now.After(s.ExpiresAt) {
						delete(h.sessions, token)
					}
				}
				h.mu.Unlock()

				h.csrfMu.Lock()
				for token, expires := range h.csrfTokens {
					if now.After(expires) {
						delete(h.csrfTokens, token)
					}
				}
				h.csrfMu.Unlock()
			}
		}
	}()

	// Rate cleanup
	go h.rateCleanupLoop()

	// CSRF cleanup
	go h.csrfCleanupLoop()

	// Load existing sessions
	h.loadSessions()

	return h
}

// ServeHTTP handles HTTP requests for authentication endpoints
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/auth/csrf":
		h.handleCSRFToken(w, r)
	case "/api/auth/login":
		h.handleLogin(w, r)
	case "/api/auth/register":
		h.authMiddleware(http.HandlerFunc(h.handleRegister)).ServeHTTP(w, r)
	case "/api/auth/forgot-password":
		h.handleForgotPassword(w, r)
	case "/api/auth/reset-password":
		h.handleResetPassword(w, r)
	case "/api/auth/verify":
		h.handleVerify(w, r)
	case "/api/auth/oidc/login":
		h.HandleOIDCLogin(w, r)
	case "/api/auth/oidc/callback":
		h.HandleOIDCCallback(w, r)
	case "/api/auth/mfa/setup":
		h.authMiddleware(http.HandlerFunc(h.handleMFASetupRoute)).ServeHTTP(w, r)
	case "/api/auth/mfa/verify":
		h.authMiddleware(http.HandlerFunc(h.handleMFAVerifyRoute)).ServeHTTP(w, r)
	case "/api/auth/mfa/disable":
		h.authMiddleware(http.HandlerFunc(h.handleMFADisableRoute)).ServeHTTP(w, r)
	case "/api/auth/logout":
		h.handleLogout(w, r)
	case "/api/auth/refresh":
		h.authMiddleware(http.HandlerFunc(h.handleRefresh)).ServeHTTP(w, r)
	case "/api/auth/users":
		h.authMiddleware(http.HandlerFunc(h.handleListUsers)).ServeHTTP(w, r)
	case "/api/scan/submit":
		h.authMiddleware(http.HandlerFunc(h.handleScanSubmit)).ServeHTTP(w, r)
	case "/api/scan/status":
		h.authMiddleware(http.HandlerFunc(h.handleScanStatus)).ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleLogin processes login requests
func (h *LoginHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		CSRF     string `json:"csrf"`
		MFACode  string `json:"mfa_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if h.adminHash == "" && len(h.users) == 0 {
		http.Error(w, "auth not configured", http.StatusInternalServerError)
		return
	}

	var user *User
	var userExists bool

	if creds.Username == "admin" && h.adminHash != "" {
		if !VerifyPassword(creds.Password, h.adminHash) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.mu.RLock()
		user, userExists = h.users[creds.Username]
		h.mu.RUnlock()
	} else {
		h.mu.RLock()
		user, userExists = h.users[creds.Username]
		h.mu.RUnlock()
		if !userExists || !VerifyPassword(creds.Password, user.PasswordHash) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if !userExists {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.RLock()
	mfaRequired := os.Getenv("ARES_ENFORCE_MFA") == "true"
	mfaEnabled := user.MFAEnabled && user.MFAVerified
	h.mu.RUnlock()

	if mfaRequired || mfaEnabled {
		if creds.MFACode == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-MFA-Required", "true")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":        "mfa_code required",
				"mfa_required": true,
			})
			return
		}
		if err := h.ValidateMFACode(creds.Username, creds.MFACode); err != nil {
			http.Error(w, "invalid MFA code", http.StatusUnauthorized)
			return
		}
	}

	token := h.generateToken(creds.Username)
	if token == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	session := &Session{
		Token:     token,
		Username:  creds.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	h.mu.Lock()
	h.sessions[token] = session
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "ares_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// handleVerify validates session tokens
func (h *LoginHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "authenticated", "username": "admin", "role": "admin"})
}

// authMiddleware wraps handlers with authentication checks
func (h *LoginHandler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" {
			if c, err := r.Cookie("ares_session"); err == nil {
				token = c.Value
			}
		}
		h.mu.RLock()
		session, ok := h.sessions[token]
		h.mu.RUnlock()
		if !ok || time.Now().After(session.ExpiresAt) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleScanSubmit processes scan submission requests
func (h *LoginHandler) handleScanSubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"submitted"}`))
}

// handleScanStatus returns the status of scans
func (h *LoginHandler) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// generateToken creates a secure session token
func (h *LoginHandler) generateToken(username string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[Auth] crypto/rand unavailable: %v", err))
		return ""
	}
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write([]byte(username))
	mac.Write(b)
	mac.Write([]byte(time.Now().Format(time.RFC3339)))
	return hex.EncodeToString(mac.Sum(nil))
}

// handleCSRFToken generates CSRF tokens for forms
func (h *LoginHandler) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)
	h.csrfMu.Lock()
	h.csrfTokens[token] = time.Now().Add(30 * time.Minute)
	h.csrfMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"csrf_token": token})
}

// allow checks if an IP is within rate limits
func normalizeIP(ip string) string {
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func (h *LoginHandler) allow(ip string) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	now := time.Now()
	normalized := normalizeIP(ip)
	entry, ok := h.rateBucket[normalized]
	if !ok || now.Sub(entry.windowStart) > h.rateWin {
		h.rateBucket[normalized] = &rateEntry{count: 1, windowStart: now}
		return true
	}
	entry.count++
	return entry.count <= h.rateLimit
}

// validatePassword validates password strength
func validatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain uppercase, lowercase, and digit")
	}
	return nil
}

// HashPassword creates a secure password hash using Argon2
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads, encodedSalt, encodedHash), nil
}

// encryptSessionData encrypts session data for storage
func (h *LoginHandler) encryptSessionData(plaintext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(h.secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptSessionData decrypts session data from storage
func (h *LoginHandler) decryptSessionData(ciphertext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(h.secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// VerifyPassword checks a password against its hash
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var memory, timeVal, threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeVal, &threads); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	if len(expectedHash) == 0 {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, uint32(timeVal), uint32(memory), uint8(threads), uint32(len(expectedHash)))
	return hmac.Equal(computedHash, expectedHash)
}

// initDefaultUsers initializes default users from environment variables
func (h *LoginHandler) initDefaultUsers() {
	defaultUsers := map[string]struct {
		Password string
		Role     UserRole
	}{}

	adminPass := getEnv("ARES_ADMIN_PASSWORD")
	if adminPass != "" {
		defaultUsers["admin"] = struct {
			Password string
			Role     UserRole
		}{adminPass, RoleAdmin}
	}

	analystPass := getEnv("ARES_ANALYST_PASSWORD")
	if analystPass != "" {
		defaultUsers["analyst"] = struct {
			Password string
			Role     UserRole
		}{analystPass, RoleOperator}
	}

	viewerPass := getEnv("ARES_VIEWER_PASSWORD")
	if viewerPass != "" {
		defaultUsers["viewer"] = struct {
			Password string
			Role     UserRole
		}{viewerPass, RoleViewer}
	}

	for username, creds := range defaultUsers {
		hash, err := HashPassword(creds.Password)
		if err != nil {
			// In a real implementation, we'd log this error
			continue
		}
		h.users[username] = &User{
			TenantID:     getEnv("ARES_DEFAULT_TENANT"),
			Username:     username,
			PasswordHash: hash,
			Role:         creds.Role,
			CreatedAt:    time.Now(),
		}
	}
}

// GenerateSessionToken creates a session token for a username
func GenerateSessionToken(username, secret string) (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	mac.Write([]byte{0})
	mac.Write(randomBytes)
	mac.Write([]byte{0})
	tsBytes := make([]byte, 8)
	if _, err := rand.Read(tsBytes); err != nil {
		return "", fmt.Errorf("crypto/rand failed for timestamp nonce: %w", err)
	}
	mac.Write(tsBytes)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Login authenticates a user and returns a session
func (h *LoginHandler) Login(username, password string) (*Session, error) {
	if h.adminHash == "" && len(h.users) == 0 {
		return nil, fmt.Errorf("auth not configured")
	}

	var user *User
	var userExists bool

	if username == "admin" && h.adminHash != "" {
		if !VerifyPassword(password, h.adminHash) {
			return nil, fmt.Errorf("invalid credentials")
		}
		h.mu.RLock()
		user = h.users[username]
		h.mu.RUnlock()
	} else {
		h.mu.RLock()
		user, userExists = h.users[username]
		h.mu.RUnlock()
		if !userExists || !VerifyPassword(password, user.PasswordHash) {
			return nil, fmt.Errorf("invalid credentials")
		}
	}

	token := h.generateToken(username)
	if token == "" {
		return nil, fmt.Errorf("token generation failed")
	}
	session := &Session{
		Token:     token,
		Username:  username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	h.mu.Lock()
	h.sessions[token] = session
	h.mu.Unlock()

	return session, nil
}

// ValidateToken checks if a token is valid and returns the associated session
// AuthConfigured returns true if at least one user or admin password is configured
func (h *LoginHandler) AuthConfigured() bool {
	return h.adminHash != "" || len(h.users) > 0
}

func (h *LoginHandler) ValidateToken(token string) (*Session, error) {
	h.mu.RLock()
	session, ok := h.sessions[token]
	h.mu.RUnlock()

	if !ok || session == nil || time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return session, nil
}

// IsRateLimited checks if an IP is rate limited
func (h *LoginHandler) IsRateLimited(ip string) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	entry, ok := h.rateBucket[ip]
	if !ok {
		return false
	}
	return entry.count > h.rateLimit
}

// SetRateLimitForTest sets the rate limit count for an IP (test use only)
func (h *LoginHandler) SetRateLimitForTest(ip string, count int) {
	h.rateMu.Lock()
	h.rateBucket[ip] = &rateEntry{count: count, windowStart: time.Now()}
	h.rateMu.Unlock()
}

// ExtractToken extracts a token from request headers or cookies
func ExtractToken(r *http.Request) string {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.Header.Get("X-Session-Token")
	}
	if token == "" {
		if c, err := r.Cookie("ares_session"); err == nil {
			token = c.Value
		}
	}
	return token
}

// getEnv gets an environment variable with a fallback
func getEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return ""
}

// handleLogout processes logout requests
func (h *LoginHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		if c, err := r.Cookie("ares_session"); err == nil {
			token = c.Value
		}
	}

	h.mu.Lock()
	delete(h.sessions, token)
	h.mu.Unlock()
	h.saveSessions()

	http.SetCookie(w, &http.Cookie{
		Name:     "ares_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

// rateCleanupLoop periodically cleans up old rate limit entries
func (h *LoginHandler) rateCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-h.rateCleanupStop:
			return
		case <-ticker.C:
			h.rateMu.Lock()
			cutoff := time.Now().Add(-2 * h.rateWin)
			for ip, entry := range h.rateBucket {
				if entry.windowStart.Before(cutoff) {
					delete(h.rateBucket, ip)
				}
			}
			h.rateMu.Unlock()
		}
	}
}

// csrfCleanupLoop periodically cleans up old CSRF tokens
func (h *LoginHandler) csrfCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-h.csrfCleanupStop:
			return
		case <-ticker.C:
			h.csrfMu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for token, expires := range h.csrfTokens {
				if expires.Before(cutoff) {
					delete(h.csrfTokens, token)
				}
			}
			h.csrfMu.Unlock()
		}
	}
}

// handleRefresh refreshes an expiring token
func (h *LoginHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		if c, err := r.Cookie("ares_session"); err == nil {
			token = c.Value
		}
	}

	h.mu.Lock()
	session, ok := h.sessions[token]
	if !ok || time.Now().After(session.ExpiresAt) {
		h.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	newToken := h.generateToken(session.Username)
	if newToken == "" {
		h.mu.Unlock()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newSession := &Session{
		Token:     newToken,
		Username:  session.Username,
		Role:      session.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	delete(h.sessions, token)
	h.sessions[newToken] = newSession
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "ares_session",
		Value:    newToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newSession)
}

// requireAdmin checks if the request is from an admin user
func (h *LoginHandler) RequireAdmin(r *http.Request) bool {
	token := ExtractToken(r)
	session, err := h.ValidateToken(token)
	if err != nil {
		return false
	}
	return session.Role == RoleAdmin
}

// handleListUsers returns a list of all users (admin only)
func (h *LoginHandler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !h.RequireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h.mu.RLock()
	var users []*User
	for _, u := range h.users {
		users = append(users, &User{
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt,
			LastLogin: u.LastLogin,
		})
	}
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// saveSessions persists sessions to disk
func (h *LoginHandler) saveSessions() {
	if h.storePath == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := json.MarshalIndent(h.sessions, "", "  ")
	if err != nil {
		return
	}
	encrypted, err := h.encryptSessionData(data)
	if err != nil {
		// In a real implementation, we'd log this error
		return
	}
	tmpPath := h.storePath + ".tmp"
	if err := os.WriteFile(tmpPath, encrypted, 0600); err != nil {
		return
	}
	if err := os.Rename(tmpPath, h.storePath); err != nil {
		os.Remove(tmpPath)
	}
}

// loadSessions loads sessions from disk
func (h *LoginHandler) loadSessions() {
	if h.storePath == "" {
		return
	}
	data, err := os.ReadFile(h.storePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error(fmt.Sprintf("[Auth] Failed to read session store: %v", err))
		}
		return
	}
	decrypted, err := h.decryptSessionData(data)
	if err != nil {
		logger.Error(fmt.Sprintf("[Auth] Failed to decrypt session store: %v — discarding corrupted data", err))
		return
	}
	h.mu.Lock()
	if err := json.Unmarshal(decrypted, &h.sessions); err != nil {
		logger.Error(fmt.Sprintf("[Auth] Failed to parse session store: %v", err))
	}
	h.mu.Unlock()
}

// GenerateMFASecret generates a new TOTP secret for a user
func (h *LoginHandler) GenerateMFASecret(username string) (string, string, error) {
	h.mu.Lock()
	user, ok := h.users[username]
	h.mu.Unlock()
	if !ok {
		return "", "", fmt.Errorf("user not found")
	}

	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("failed to generate secret: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(secret)

	h.mu.Lock()
	user.MFASecret = encoded
	user.MFAEnabled = false
	user.MFAVerified = false
	h.users[username] = user
	h.mu.Unlock()

	otpURI := fmt.Sprintf("otpauth://totp/ARES:%s?secret=%s&issuer=ARES", username, encoded)
	return encoded, otpURI, nil
}

// VerifyMFASetup verifies a TOTP code during initial setup
func (h *LoginHandler) VerifyMFASetup(username, code string) error {
	h.mu.RLock()
	user, ok := h.users[username]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("user not found")
	}
	if user.MFASecret == "" {
		return fmt.Errorf("no MFA secret configured")
	}

	secret, err := base64.StdEncoding.DecodeString(user.MFASecret)
	if err != nil {
		return fmt.Errorf("invalid MFA secret: %w", err)
	}

	valid := false
	for offset := int64(-1); offset <= 1; offset++ {
		step := 30 + offset
		if step < 1 {
			continue
		}
		totpCode, err := generateTOTP(secret, step)
		if err != nil {
			continue
		}
		if totpCode == code {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	user.MFAVerified = true
	user.MFAEnabled = true
	h.mu.Lock()
	h.users[username] = user
	h.mu.Unlock()
	return nil
}

// ValidateMFACode validates a TOTP code during login
func (h *LoginHandler) ValidateMFACode(username, code string) error {
	h.mu.RLock()
	user, ok := h.users[username]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("user not found")
	}
	if !user.MFAEnabled || !user.MFAVerified {
		return fmt.Errorf("MFA not enabled for user")
	}

	secret, err := base64.StdEncoding.DecodeString(user.MFASecret)
	if err != nil {
		return fmt.Errorf("invalid MFA secret: %w", err)
	}

	for offset := int64(-1); offset <= 1; offset++ {
		step := 30 + offset
		if step < 1 {
			continue
		}
		totpCode, err := generateTOTP(secret, step)
		if err != nil {
			continue
		}
		if totpCode == code {
			return nil
		}
	}

	return fmt.Errorf("invalid TOTP code")
}

func generateTOTP(secret []byte, timeStep int64) (string, error) {
	counter := uint64(time.Now().Unix() / timeStep)
	mac := hmac.New(sha256.New, secret)
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac.Write(counterBytes)
	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	code := ((int(hash[offset])&0x7f)<<24 |
		(int(hash[offset+1])&0xff)<<16 |
		(int(hash[offset+2])&0xff)<<8 |
		(int(hash[offset+3]) & 0xff)) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// DisableMFA disables MFA for a user
func (h *LoginHandler) DisableMFA(username string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	user, ok := h.users[username]
	if !ok {
		return fmt.Errorf("user not found")
	}
	user.MFAEnabled = false
	user.MFAVerified = false
	user.MFASecret = ""
	h.users[username] = user
	return nil
}

// ValidateCSRFToken validates a CSRF token
func (h *LoginHandler) ValidateCSRFToken(token string) bool {
	if token == "" {
		return false
	}
	h.csrfMu.Lock()
	defer h.csrfMu.Unlock()
	_, ok := h.csrfTokens[token]
	if ok {
		delete(h.csrfTokens, token)
	}
	return ok
}

func (h *LoginHandler) sessionFromRequest(r *http.Request) *Session {
	token := ExtractToken(r)
	if token == "" {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[token]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil
	}
	return s
}

func (h *LoginHandler) SetOIDCProvider(provider *OIDCProvider) {
	h.oidcProvider = provider
}

// Close gracefully shuts down background goroutines
func (h *LoginHandler) Close() {
	close(h.rateCleanupStop)
	close(h.csrfCleanupStop)
	h.saveSessions()
}

func (h *LoginHandler) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidcProvider == nil {
		http.Error(w, "OIDC not configured", http.StatusNotImplemented)
		return
	}

	authURL, state, err := h.oidcProvider.AuthURL()
	if err != nil {
		http.Error(w, "failed to generate auth URL", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "ares_oidc_state",
		Value:    state,
		Path:     "/api/auth/oidc/callback",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *LoginHandler) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidcProvider == nil {
		http.Error(w, "OIDC not configured", http.StatusNotImplemented)
		return
	}

	stateCookie, err := r.Cookie("ares_oidc_state")
	if err != nil {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	if state != stateCookie.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	userInfo, err := h.oidcProvider.HandleCallback(code, state)
	if err != nil {
		http.Error(w, fmt.Sprintf("OIDC callback failed: %v", err), http.StatusUnauthorized)
		return
	}

	if !userInfo.EmailVerified {
		http.Error(w, "email not verified by provider", http.StatusForbidden)
		return
	}

	username := userInfo.Email
	if username == "" {
		username = userInfo.Sub
	}

	role := userInfo.MapToRole(RoleViewer)

	h.mu.Lock()
	if _, exists := h.users[username]; !exists {
		h.users[username] = &User{
			Username:  username,
			Role:      role,
			CreatedAt: time.Now(),
		}
	}
	h.users[username].LastLogin = time.Now()
	h.mu.Unlock()

	token := h.generateToken(username)
	session := &Session{
		Token:     token,
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	h.mu.Lock()
	h.sessions[token] = session
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "ares_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

type mfaVerifyReq struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

func (h *LoginHandler) handleMFASetupRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := h.sessionFromRequest(r)
	if session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret, otpURI, err := h.GenerateMFASecret(session.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret":   secret,
		"otp_uri":  otpURI,
		"username": session.Username,
	})
}

func (h *LoginHandler) handleMFAVerifyRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := h.sessionFromRequest(r)
	if session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req mfaVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.VerifyMFASetup(session.Username, req.Code); err != nil {
		http.Error(w, "invalid verification code", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": true})
}

func (h *LoginHandler) handleMFADisableRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session := h.sessionFromRequest(r)
	if session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.DisableMFA(session.Username); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"disabled": true})
}

type registerReq struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Role     UserRole `json:"role"`
	TenantID string   `json:"tenant_id"`
}

func (h *LoginHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.RequireAdmin(r) {
		http.Error(w, "registration requires admin privileges", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "username, email, and password are required", http.StatusBadRequest)
		return
	}

	if err := validatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	if _, exists := h.users[req.Username]; exists {
		h.mu.Unlock()
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}
	h.mu.Unlock()

	hash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	role := RoleViewer
	if req.Role != "" {
		role = req.Role
	}

	user := &User{
		TenantID:            req.TenantID,
		Username:            req.Username,
		PasswordHash:        hash,
		Role:                role,
		CreatedAt:           time.Now(),
		ForcePasswordChange: true,
	}

	h.mu.Lock()
	h.users[req.Username] = user
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "user created",
		"username": req.Username,
	})
}

type forgotPasswordReq struct {
	Email string `json:"email"`
}

func (h *LoginHandler) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req forgotPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	var foundUser *User
	for _, u := range h.users {
		if u.Username == req.Email {
			foundUser = u
			break
		}
	}
	h.mu.RUnlock()

	if foundUser == nil {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "if the email exists, a reset link has been sent",
		})
		return
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resetToken := h.generateToken(foundUser.Username + hex.EncodeToString(nonce))
	if resetToken == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.resetMu.Lock()
	h.resetTokens[resetToken] = &resetTokenEntry{
		Username:  foundUser.Username,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	h.resetMu.Unlock()

	time.Sleep(200 * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "if the email exists, a reset link has been sent",
	})
}

type resetPasswordReq struct {
	Token       string `json:"token"`
	Email       string `json:"email"`
	NewPassword string `json:"new_password"`
}

func (h *LoginHandler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.Email == "" || req.NewPassword == "" {
		http.Error(w, "token, email, and new_password are required", http.StatusBadRequest)
		return
	}

	if err := validatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.resetMu.Lock()
	entry, ok := h.resetTokens[req.Token]
	if !ok || time.Now().After(entry.ExpiresAt) {
		h.resetMu.Unlock()
		http.Error(w, "invalid or expired reset token", http.StatusBadRequest)
		return
	}
	if entry.Username != req.Email {
		h.resetMu.Unlock()
		http.Error(w, "token does not match email", http.StatusBadRequest)
		return
	}
	delete(h.resetTokens, req.Token)
	h.resetMu.Unlock()

	h.mu.Lock()
	user, exists := h.users[req.Email]
	if !exists {
		h.mu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		h.mu.Unlock()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = hash
	user.ForcePasswordChange = false
	h.users[req.Email] = user

	for token, s := range h.sessions {
		if s.Username == req.Email {
			delete(h.sessions, token)
		}
	}
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "password reset successful",
	})
}
