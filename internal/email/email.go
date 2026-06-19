package email

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/secrets"
	"github.com/ares/engine/internal/uuid"
)

type EmailType string

const (
	EmailWelcome           EmailType = "welcome"
	EmailPasswordReset     EmailType = "password_reset"
	EmailEmailVerification EmailType = "email_verification"
	EmailInvoice           EmailType = "invoice"
	EmailAlert             EmailType = "alert"
)

type EmailRequest struct {
	To      string
	Subject string
	Type    EmailType
	Data    map[string]interface{}
}

type Provider interface {
	Send(req EmailRequest) error
}

type SMTPProvider struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool
}

func (p *SMTPProvider) Send(req EmailRequest) error {
	auth := smtp.PlainAuth("", p.Username, p.Password, p.Host)

	body, err := RenderTemplate(req.Type, req.Data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	safeFrom := stripHeaderNewlines(p.From)
	safeTo := stripHeaderNewlines(req.To)
	safeSubject := stripHeaderNewlines(req.Subject)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		safeFrom, safeTo, safeSubject, body)

	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)

	if p.UseTLS {
		tlsConfig := &tls.Config{
			ServerName: p.Host,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, p.Host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		defer client.Close()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}

		if err := client.Mail(p.Username); err != nil {
			return fmt.Errorf("smtp mail: %w", err)
		}

		if err := client.Rcpt(req.To); err != nil {
			return fmt.Errorf("smtp rcpt: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("smtp write: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("smtp close: %w", err)
		}
	} else {
		err = smtp.SendMail(addr, auth, p.From, []string{req.To}, []byte(msg))
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}
	}

	logger.Info("[Email] Sent email to %s", logger.Fields{"to": req.To, "type": req.Type})
	return nil
}

type SendGridProvider struct {
	APIKey string
	From   string
}

func (p SendGridProvider) Send(req EmailRequest) error {
	logger.Info("[Email] SendGrid would send email to %s", logger.Fields{"to": req.To, "type": req.Type})
	return nil
}

type SESProvider struct {
	Region    string
	AccessKey string
	SecretKey string
	From      string
}

func (p SESProvider) Send(req EmailRequest) error {
	logger.Info("[Email] SES would send email to %s", logger.Fields{"to": req.To, "type": req.Type})
	return nil
}

type MockProvider struct{}

func (p MockProvider) Send(req EmailRequest) error {
	logger.Info("[Email] Mock: Would send %s to %s", logger.Fields{"type": req.Type, "to": req.To})
	return nil
}

var emailTemplates = map[EmailType]string{
	EmailWelcome: `
<!DOCTYPE html>
<html>
<head><title>Welcome to ARES Engine</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
<h1 style="color: white; margin: 0;">Welcome to ARES Engine!</h1>
</div>
<div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
<p>Hi {{.Name}},</p>
<p>Thank you for joining ARES Engine, your automated security testing platform.</p>
<p>Your account has been created successfully. You can now start scanning your applications for vulnerabilities.</p>
<p><a href="{{.DashboardURL}}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">Go to Dashboard</a></p>
<p>If you have any questions, feel free to reach out to our support team.</p>
<p>Best regards,<br>The ARES Engine Team</p>
</div>
</body>
</html>
`,
	EmailPasswordReset: `
<!DOCTYPE html>
<html>
<head><title>Password Reset Request</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #ff6b6b; padding: 30px; border-radius: 10px 10px 0 0;">
<h1 style="color: white; margin: 0;">Password Reset Request</h1>
</div>
<div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
<p>Hi {{.Name}},</p>
<p>We received a request to reset your password. Click the button below to create a new password:</p>
<p><a href="{{.ResetURL}}" style="background: #ff6b6b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">Reset Password</a></p>
<p>This link will expire in {{.ExpiryHours}} hours.</p>
<p>If you didn't request this, you can safely ignore this email.</p>
<p>Best regards,<br>The ARES Engine Team</p>
</div>
</body>
</html>
`,
	EmailEmailVerification: `
<!DOCTYPE html>
<html>
<head><title>Verify Your Email</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #4ecdc4; padding: 30px; border-radius: 10px 10px 0 0;">
<h1 style="color: white; margin: 0;">Verify Your Email</h1>
</div>
<div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
<p>Hi {{.Name}},</p>
<p>Please verify your email address by clicking the button below:</p>
<p><a href="{{.VerificationURL}}" style="background: #4ecdc4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">Verify Email</a></p>
<p>This link will expire in {{.ExpiryHours}} hours.</p>
<p>Best regards,<br>The ARES Engine Team</p>
</div>
</body>
</html>
`,
	EmailInvoice: `
<!DOCTYPE html>
<html>
<head><title>Your Invoice</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #2c3e50; padding: 30px; border-radius: 10px 10px 0 0;">
<h1 style="color: white; margin: 0;">Invoice #{{.InvoiceNumber}}</h1>
</div>
<div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
<p>Hi {{.Name}},</p>
<p>Your invoice for {{.PlanName}} is ready.</p>
<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
<tr><td style="padding: 10px; border-bottom: 1px solid #ddd;">Amount:</td><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>{{.Amount}}</strong></td></tr>
<tr><td style="padding: 10px; border-bottom: 1px solid #ddd;">Due Date:</td><td style="padding: 10px; border-bottom: 1px solid #ddd;">{{.DueDate}}</td></tr>
<tr><td style="padding: 10px; border-bottom: 1px solid #ddd;">Status:</td><td style="padding: 10px; border-bottom: 1px solid #ddd;">{{.Status}}</td></tr>
</table>
<p><a href="{{.InvoiceURL}}" style="background: #2c3e50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">View Invoice</a></p>
<p>Best regards,<br>The ARES Engine Team</p>
</div>
</body>
</html>
`,
	EmailAlert: `
<!DOCTYPE html>
<html>
<head><title>Security Alert</title></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #e74c3c; padding: 30px; border-radius: 10px 10px 0 0;">
<h1 style="color: white; margin: 0;">Security Alert</h1>
</div>
<div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
<p>Hi {{.Name}},</p>
<p>{{.AlertMessage}}</p>
<p><a href="{{.DashboardURL}}" style="background: #e74c3c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;">View Details</a></p>
<p>Best regards,<br>The ARES Engine Team</p>
</div>
</body>
</html>
`,
}

var templateCache sync.Map

func RenderTemplate(emailType EmailType, data map[string]interface{}) (string, error) {
	tmplText, ok := emailTemplates[emailType]
	if !ok {
		return "", fmt.Errorf("template not found: %s", emailType)
	}

	tmpl, ok := templateCache.Load(emailType)
	if !ok {
		parsed, err := template.New(string(emailType)).Parse(tmplText)
		if err != nil {
			return "", fmt.Errorf("parse template: %w", err)
		}
		templateCache.Store(emailType, parsed)
		tmpl = parsed
	}

	var buf bytes.Buffer
	if err := tmpl.(*template.Template).Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

type Manager struct {
	provider Provider
	mu       sync.RWMutex
	queue    []EmailRequest
}

func NewManager() (*Manager, error) {
	var provider Provider

	sendGridKey := secrets.Get("SENDGRID_API_KEY")
	sesKey := secrets.Get("AWS_SES_ACCESS_KEY")
	smtpHost := secrets.Get("SMTP_HOST")

	if sendGridKey != "" {
		provider = SendGridProvider{
			APIKey: sendGridKey,
			From:   secrets.Get("EMAIL_FROM"),
		}
		logger.Info("[Email] Using SendGrid provider")
	} else if sesKey != "" {
		provider = SESProvider{
			Region:    secrets.Get("AWS_REGION"),
			AccessKey: sesKey,
			SecretKey: secrets.Get("AWS_SES_SECRET_KEY"),
			From:      secrets.Get("EMAIL_FROM"),
		}
		logger.Info("[Email] Using AWS SES provider")
	} else if smtpHost != "" {
		provider = &SMTPProvider{
			Host:     smtpHost,
			Port:     parseIntOrDefault(secrets.Get("SMTP_PORT"), 587),
			Username: secrets.Get("SMTP_USERNAME"),
			Password: secrets.Get("SMTP_PASSWORD"),
			From:     secrets.Get("EMAIL_FROM"),
			UseTLS:   secrets.Get("SMTP_USE_TLS") == "true",
		}
		logger.Info("[Email] Using SMTP provider")
	} else {
		provider = &MockProvider{}
		logger.Warn("[Email] No email provider configured, using mock")
	}

	return &Manager{
		provider: provider,
		queue:    make([]EmailRequest, 0),
	}, nil
}

func (m *Manager) Send(req EmailRequest) error {
	return m.provider.Send(req)
}

func (m *Manager) SendWelcome(to, name, dashboardURL string) error {
	return m.Send(EmailRequest{
		To:      to,
		Subject: "Welcome to ARES Engine!",
		Type:    EmailWelcome,
		Data: map[string]interface{}{
			"Name":         name,
			"DashboardURL": dashboardURL,
		},
	})
}

func (m *Manager) SendPasswordReset(to, name, resetURL string, expiryHours int) error {
	return m.Send(EmailRequest{
		To:      to,
		Subject: "Password Reset Request",
		Type:    EmailPasswordReset,
		Data: map[string]interface{}{
			"Name":        name,
			"ResetURL":    resetURL,
			"ExpiryHours": expiryHours,
		},
	})
}

func (m *Manager) SendEmailVerification(to, name, verificationURL string, expiryHours int) error {
	return m.Send(EmailRequest{
		To:      to,
		Subject: "Verify Your Email Address",
		Type:    EmailEmailVerification,
		Data: map[string]interface{}{
			"Name":            name,
			"VerificationURL": verificationURL,
			"ExpiryHours":     expiryHours,
		},
	})
}

func (m *Manager) SendInvoice(to, name, invoiceNumber, planName, amount, dueDate, status, invoiceURL string) error {
	return m.Send(EmailRequest{
		To:      to,
		Subject: fmt.Sprintf("Invoice #%s", invoiceNumber),
		Type:    EmailInvoice,
		Data: map[string]interface{}{
			"Name":          name,
			"InvoiceNumber": invoiceNumber,
			"PlanName":      planName,
			"Amount":        amount,
			"DueDate":       dueDate,
			"Status":        status,
			"InvoiceURL":    invoiceURL,
		},
	})
}

func (m *Manager) SendAlert(to, name, alertMessage, dashboardURL string) error {
	return m.Send(EmailRequest{
		To:      to,
		Subject: "Security Alert - ARES Engine",
		Type:    EmailAlert,
		Data: map[string]interface{}{
			"Name":         name,
			"AlertMessage": alertMessage,
			"DashboardURL": dashboardURL,
		},
	})
}

func (m *Manager) Queue(req EmailRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queue = append(m.queue, req)
}

func (m *Manager) ProcessQueue() []error {
	m.mu.Lock()
	queue := make([]EmailRequest, len(m.queue))
	copy(queue, m.queue)
	m.queue = m.queue[:0]
	m.mu.Unlock()

	var errs []error
	for _, req := range queue {
		if err := m.Send(req); err != nil {
			errs = append(errs, err)
			logger.Error(fmt.Sprintf("[Email] Failed to send email: %v", err))
		}
	}

	return errs
}

func parseIntOrDefault(value string, defaultValue int) int {
	var result int
	if _, err := fmt.Sscanf(value, "%d", &result); err != nil {
		return defaultValue
	}
	return result
}

func stripHeaderNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

func SanitizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]TokenData
}

type TokenData struct {
	Token     string
	Email     string
	Type      EmailType
	ExpiresAt time.Time
	Data      map[string]interface{}
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]TokenData),
	}
}

func (ts *TokenStore) CreateToken(email string, tokenType EmailType, expiry time.Duration, data map[string]interface{}) string {
	token := generateToken()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tokens[token] = TokenData{
		Token:     token,
		Email:     email,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(expiry),
		Data:      data,
	}
	return token
}

func (ts *TokenStore) ValidateToken(token string) (*TokenData, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	data, ok := ts.tokens[token]
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	if time.Now().After(data.ExpiresAt) {
		delete(ts.tokens, token)
		return nil, fmt.Errorf("token expired")
	}

	return &data, nil
}

func (ts *TokenStore) InvalidateToken(token string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tokens, token)
}

func (ts *TokenStore) Cleanup() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for token, data := range ts.tokens {
		if now.After(data.ExpiresAt) {
			delete(ts.tokens, token)
		}
	}
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return uuid.New()
	}
	return hex.EncodeToString(b)
}
