package proxyimport

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BurpRequest represents a single request imported from Burp Suite or Caido.
type BurpRequest struct {
	Method  string
	URL     string
	Host    string
	Port    int
	Protocol string
	Path    string
	Headers map[string]string
	Body    []byte
	Raw     []byte // The full raw HTTP request
}

// BurpItem is the XML structure for Burp Suite's exported items.
type BurpItem struct {
	XMLName  xml.Name `xml:"item"`
	Method   string   `xml:"method"`
	URL      string   `xml:"url"`
	Host     string   `xml:"host"`
	Port     int      `xml:"port"`
	Protocol string   `xml:"protocol"`
	Path     string   `xml:"path"`
	Request  string   `xml:"request"` // Base64-encoded raw request
}

// BurpExport is the root XML element from Burp Suite exports.
type BurpExport struct {
	XMLName xml.Name   `xml:"items"`
	Items   []BurpItem `xml:"item"`
}

// CaidoRequest represents a request from Caido's API export.
type CaidoRequest struct {
	ID      string `json:"id"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	Body string `json:"body,omitempty"`
}

// ParseBurpXML parses a Burp Suite exported XML file and returns HTTP requests.
// The Burp export format base64-encodes the raw HTTP request.
func ParseBurpXML(data []byte) ([]BurpRequest, error) {
	var export BurpExport
	if err := xml.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("parse burp xml: %w", err)
	}

	requests := make([]BurpRequest, 0, len(export.Items))
	for _, item := range export.Items {
		// Decode base64 request
		raw, err := base64.StdEncoding.DecodeString(item.Request)
		if err != nil {
			// Try without padding
			raw, err = base64.RawStdEncoding.DecodeString(item.Request)
			if err != nil {
				continue // skip malformed items
			}
		}

		req, err := parseRawHTTPRequest(raw)
		if err != nil {
			// Fall back to XML metadata
			req = &BurpRequest{
				Method:   item.Method,
				URL:      item.URL,
				Host:     item.Host,
				Port:     item.Port,
				Protocol: item.Protocol,
				Path:     item.Path,
				Raw:      raw,
				Headers:  make(map[string]string),
			}
		}

		requests = append(requests, *req)
	}

	return requests, nil
}

// ParseRawRequest parses a raw HTTP request string (from Caido, Burp, or manual).
// Format: "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
func ParseRawRequest(raw []byte) (*BurpRequest, error) {
	return parseRawHTTPRequest(raw)
}

// parseRawHTTPRequest parses raw HTTP request bytes into a BurpRequest.
func parseRawHTTPRequest(raw []byte) (*BurpRequest, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse http request: %w", err)
	}
	defer req.Body.Close()

	br := &BurpRequest{
		Method:  req.Method,
		Headers: make(map[string]string),
		Raw:     raw,
	}

	// Reconstruct URL from request
	if req.URL != nil {
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		br.URL = req.URL.String()
		br.Path = req.URL.Path
	}

	// Copy headers
	for key, vals := range req.Header {
		if len(vals) > 0 {
			br.Headers[key] = vals[0]
			if strings.ToLower(key) == "host" {
				br.Host = vals[0]
			}
		}
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	if err == nil && len(body) > 0 {
		br.Body = body
	}

	// Determine protocol scheme from headers or URL
	if br.Protocol == "" {
		if strings.EqualFold(br.Headers["X-Forwarded-Proto"], "https") ||
			strings.HasPrefix(br.URL, "https://") {
			br.Protocol = "https"
		} else {
			br.Protocol = "http"
		}
	}

	return br, nil
}

// ToHTTPRequest converts a BurpRequest to a standard http.Request for replay.
func (br *BurpRequest) ToHTTPRequest() (*http.Request, error) {
	var targetURL string
	if br.URL != "" {
		targetURL = br.URL
	} else {
		scheme := br.Protocol
		if scheme == "" {
			scheme = "http"
		}
		host := br.Host
		if host == "" {
			host = "localhost"
		}
		portSuffix := ""
		if br.Port > 0 && br.Port != 80 && br.Port != 443 {
			portSuffix = fmt.Sprintf(":%d", br.Port)
		}
		targetURL = fmt.Sprintf("%s://%s%s%s", scheme, host, portSuffix, br.Path)
	}

	var bodyReader io.Reader
	if len(br.Body) > 0 {
		bodyReader = bytes.NewReader(br.Body)
	}

	req, err := http.NewRequest(br.Method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	for key, val := range br.Headers {
		req.Header.Set(key, val)
	}

	return req, nil
}

// ImportFromBurpFile reads a Burp Suite XML export file and returns parsed requests.
func ImportFromBurpFile(filename string) ([]BurpRequest, error) {
	// Read file - caller handles file I/O
	return nil, fmt.Errorf("use ParseBurpXML with file contents read by caller")
}

// ImportFromCaidoJSON parses a Caido JSON export into BurpRequests.
func ImportFromCaidoJSON(data []byte) ([]BurpRequest, error) {
	// Caido exports can be a single request or an array
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		return parseCaidoArray(data)
	}
	return parseCaidoSingle(data)
}

func parseCaidoArray(data []byte) ([]BurpRequest, error) {
	// Caido array format: [{...}, {...}]
	// For now, parse as raw HTTP requests if they look like raw HTTP
	lines := strings.Split(string(data), "\n")
	var requests []BurpRequest
	var current []byte

	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") ||
			strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "DELETE ") ||
			strings.HasPrefix(line, "PATCH ") || strings.HasPrefix(line, "HEAD ") ||
			strings.HasPrefix(line, "OPTIONS ") {
			if len(current) > 0 {
				req, err := parseRawHTTPRequest(current)
				if err == nil {
					requests = append(requests, *req)
				}
				current = nil
			}
		}
		current = append(current, []byte(line+"\n")...)
	}

	// Last request
	if len(current) > 0 {
		req, err := parseRawHTTPRequest(current)
		if err == nil {
			requests = append(requests, *req)
		}
	}

	if len(requests) == 0 {
		// Fallback: treat entire data as one raw request
		req, err := parseRawHTTPRequest(data)
		if err != nil {
			return nil, fmt.Errorf("caido import: %w", err)
		}
		requests = append(requests, *req)
	}

	return requests, nil
}

func parseCaidoSingle(data []byte) ([]BurpRequest, error) {
	req, err := parseRawHTTPRequest(data)
	if err != nil {
		return nil, fmt.Errorf("caido import: %w", err)
	}
	return []BurpRequest{*req}, nil
}

// ParseURLList parses a simple list of URLs (one per line) into minimal BurpRequests.
func ParseURLList(data []byte) ([]BurpRequest, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var requests []BurpRequest

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate URL
		u, err := url.Parse(line)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}

		requests = append(requests, BurpRequest{
			Method:   "GET",
			URL:      line,
			Host:     u.Host,
			Protocol: u.Scheme,
			Path:     u.Path,
			Headers:  map[string]string{"Host": u.Host},
		})
	}

	return requests, nil
}

// IsBurpExport checks if the data looks like a Burp Suite XML export.
func IsBurpExport(data []byte) bool {
	return bytes.Contains(data, []byte("<items>")) &&
		(bytes.Contains(data, []byte("<request>")) || bytes.Contains(data, []byte("<url>")))
}

// IsRawHTTP checks if the data looks like a raw HTTP request.
func IsRawHTTP(data []byte) bool {
	firstLine := string(data)
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(firstLine, method) {
			return true
		}
	}
	return false
}
