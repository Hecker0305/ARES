package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

const EventScanStart = "scan_start"

const maxLogSize = 10 * 1024 * 1024

type AuditTrail struct {
	target string
	file   *os.File
	mu     sync.Mutex
	path   string
	size   int64
}

func New(target, path string) (*AuditTrail, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("path traversal detected: %s", path)
	}
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	f, err := os.OpenFile(absPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to stat audit log: %w", err)
	}
	return &AuditTrail{target: target, file: f, path: absPath, size: info.Size()}, nil
}

func sanitizeForAudit(s string) string {
	result := strings.ReplaceAll(s, "\n", "\\n")
	result = strings.ReplaceAll(result, "\r", "\\r")
	result = strings.ReplaceAll(result, "|", "\\|")
	return result
}

func (a *AuditTrail) rotateLocked() error {
	if a.size < maxLogSize {
		return nil
	}

	if _, err := a.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, a.file); err != nil {
		return err
	}
	checksum := hex.EncodeToString(h.Sum(nil))

	if err := a.file.Close(); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	archivePath := a.path + "." + timestamp + ".sha256-" + checksum[:16]
	if err := os.Rename(a.path, archivePath); err != nil {
		return err
	}

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	a.file = f
	a.size = 0

	return nil
}

func (a *AuditTrail) Log(fields ...string) {
	ts := time.Now().Format(time.RFC3339)
	sanitized := make([]string, len(fields))
	for i, f := range fields {
		sanitized[i] = sanitizeForAudit(f)
	}
	line := ts + " | " + strings.Join(sanitized, " | ") + "\n"

	a.mu.Lock()
	defer a.mu.Unlock()

	n, err := a.file.WriteString(line)
	if err != nil || n == 0 {
		logger.Error(fmt.Sprintf("[Audit] write error: %v (wrote %d bytes)", err, n))
		return
	}
	a.size += int64(n)
	a.file.Sync()

	if a.size >= maxLogSize {
		if err := a.rotateLocked(); err != nil {
			logger.Error(fmt.Sprintf("[Audit] rotation error: %v", err))
		}
	}
}

func (a *AuditTrail) LogFinding(id, title, severity string) {
	ts := time.Now().Format(time.RFC3339)
	line := fmt.Sprintf("%s | event=finding | id=%s | title=%s | severity=%s\n",
		ts, sanitizeForAudit(id), sanitizeForAudit(title), sanitizeForAudit(severity))

	a.mu.Lock()
	defer a.mu.Unlock()

	n, err := a.file.WriteString(line)
	if err != nil || n == 0 {
		logger.Error(fmt.Sprintf("[Audit] write error: %v (wrote %d bytes)", err, n))
		return
	}
	a.size += int64(n)
	a.file.Sync()

	if a.size >= maxLogSize {
		if err := a.rotateLocked(); err != nil {
			logger.Error(fmt.Sprintf("[Audit] rotation error: %v", err))
		}
	}
}

func (a *AuditTrail) VerifyArchive(archivePath string) (string, error) {
	expectedPrefix := "sha256-"
	idx := strings.LastIndex(archivePath, expectedPrefix)
	if idx == -1 {
		return "", fmt.Errorf("archive path does not contain checksum")
	}
	expectedChecksum := archivePath[idx+len(expectedPrefix):]
	if len(expectedChecksum) < 16 {
		return "", fmt.Errorf("invalid checksum in archive path")
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	actualChecksum := hex.EncodeToString(h.Sum(nil))

	if !strings.HasPrefix(actualChecksum, expectedChecksum) {
		return "", fmt.Errorf("checksum mismatch: expected %s..., got %s...", expectedChecksum, actualChecksum[:16])
	}

	return actualChecksum, nil
}

func (a *AuditTrail) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.file.Close()
}
