package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

// SIEMConnector handles exporting findings to enterprise security hubs.
type SIEMConnector interface {
	SendAlert(ctx context.Context, finding map[string]interface{}) error
}

// SplunkConnector pushes alerts to Splunk HEC.
type SplunkConnector struct {
	hecURL string
	token  string
	client *http.Client
}

func NewSplunkConnector(hecURL, token string) *SplunkConnector {
	return &SplunkConnector{hecURL: hecURL, token: token, client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}}
}

func (s *SplunkConnector) SendAlert(ctx context.Context, finding map[string]interface{}) error {
	if !strings.HasPrefix(strings.ToLower(s.hecURL), "https://") {
		return fmt.Errorf("splunk HEC endpoint must use HTTPS: %s", s.hecURL)
	}
	return sendWithRetry(ctx, func(ctx context.Context) error {
		payload := map[string]interface{}{"sourcetype": "ares:redteam", "event": finding}
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", s.hecURL, bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Splunk "+s.token)
		req.Header.Set("Content-Type", "application/json")
		logger.Info(fmt.Sprintf("[SIEM/Splunk] Sending alert to %s", s.hecURL))
		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("splunk HEC request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("splunk HEC returned HTTP %d", resp.StatusCode)
		}
		logger.Info(fmt.Sprintf("[SIEM/Splunk] Alert sent OK (HTTP %d)", resp.StatusCode))
		return nil
	})
}

// SentinelConnector pushes alerts to Microsoft Sentinel Log Analytics via the Data Collector API.
type SentinelConnector struct {
	workspaceID string
	sharedKey   string
	logType     string
	client      *http.Client
}

func NewSentinelConnector(workspaceID, sharedKey string) *SentinelConnector {
	return &SentinelConnector{
		workspaceID: workspaceID,
		sharedKey:   sharedKey,
		logType:     "AresRedTeam",
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

func (s *SentinelConnector) SendAlert(ctx context.Context, finding map[string]interface{}) error {
	return sendWithRetry(ctx, func(ctx context.Context) error {
		data, err := json.Marshal([]interface{}{finding})
		if err != nil {
			return err
		}

		dateStr := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
		contentLen := len(data)
		stringToHash := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", contentLen, dateStr)

		keyBytes, err := base64.StdEncoding.DecodeString(s.sharedKey)
		if err != nil {
			return fmt.Errorf("invalid sentinel shared key: %w", err)
		}
		mac := hmac.New(sha256.New, keyBytes)
		mac.Write([]byte(stringToHash))
		sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		auth := fmt.Sprintf("SharedKey %s:%s", s.workspaceID, sig)

		url := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", s.workspaceID)
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Log-Type", s.logType)
		req.Header.Set("x-ms-date", dateStr)

		logger.Info(fmt.Sprintf("[SIEM/Sentinel] Sending alert to workspace %s", s.workspaceID))
		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("sentinel request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			return fmt.Errorf("sentinel returned HTTP %d", resp.StatusCode)
		}
		logger.Info(fmt.Sprintf("[SIEM/Sentinel] Alert sent OK (HTTP %d)", resp.StatusCode))
		return nil
	})
}

func sendWithRetry(ctx context.Context, fn func(context.Context) error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			jitter, _ := rand.Int(rand.Reader, big.NewInt(1000))
			backoff += time.Duration(jitter.Int64()) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		err = fn(ctx)
		if err == nil {
			return nil
		}
		logger.Warn("[SIEM] Retry failed", logger.Fields{"attempt": attempt + 1, "error": err})
	}
	return fmt.Errorf("siem send failed after 3 retries: %w", err)
}
