package webshell

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type networkDetectResult struct {
	Path        string
	Method      string
	Status      int
	Evidence    string
	Confidence  float64
	ContentType string
}

func checkStaticFilePostResponse(ctx context.Context, baseURL string, paths []string, timeout time.Duration) []networkDetectResult {
	var results []networkDetectResult
	client := &http.Client{Timeout: timeout}

	for _, p := range paths {
		if ctxDone(ctx) {
			break
		}

		url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), strings.TrimLeft(p, "/"))

		// GET baseline
		getResp, getErr := client.Get(url)
		if getErr != nil {
			continue
		}
		getBody, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
		getResp.Body.Close()
		getLen := len(getBody)

		// POST with suspicious parameter
		postResp, postErr := client.Post(url, "application/x-www-form-urlencoded",
			strings.NewReader("cmd=id"))
		if postErr != nil {
			continue
		}
		postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 4096))
		postResp.Body.Close()
		postLen := len(postBody)

		if postResp.StatusCode != getResp.StatusCode {
			results = append(results, networkDetectResult{
				Path:       p,
				Method:     "POST",
				Status:     postResp.StatusCode,
				Confidence: 0.6,
				Evidence:   fmt.Sprintf("POST to %s returned %d vs GET %d", p, postResp.StatusCode, getResp.StatusCode),
			})
			continue
		}

		if postLen > getLen+100 {
			bodyStr := string(postBody)
			evidence := ""
			confidence := 0.5
			if strings.Contains(bodyStr, "uid=") || strings.Contains(bodyStr, "root:") ||
				strings.Contains(bodyStr, "/etc/passwd") || strings.Contains(bodyStr, "Microsoft Windows") {
				confidence = 0.9
				evidence = fmt.Sprintf("POST response contains OS command output pattern")
			} else if strings.Contains(bodyStr, "Warning:") || strings.Contains(bodyStr, "error:") {
				confidence = 0.4
				evidence = fmt.Sprintf("POST response %d bytes vs GET %d bytes with error output", postLen, getLen)
			} else {
				evidence = fmt.Sprintf("POST response %d bytes vs GET %d bytes", postLen, getLen)
			}
			results = append(results, networkDetectResult{
				Path:        p,
				Method:      "POST",
				Status:      postResp.StatusCode,
				Confidence:  confidence,
				Evidence:    evidence,
				ContentType: getResp.Header.Get("Content-Type"),
			})
		}

		if postResp.Header.Get("Content-Type") != getResp.Header.Get("Content-Type") {
			if strings.Contains(postResp.Header.Get("Content-Type"), "text/plain") ||
				strings.Contains(postResp.Header.Get("Content-Type"), "text/html") {
				results = append(results, networkDetectResult{
					Path:        p,
					Method:      "POST",
					Status:      postResp.StatusCode,
					Confidence:  0.5,
					Evidence:    fmt.Sprintf("MIME mismatch: GET %s vs POST %s", getResp.Header.Get("Content-Type"), postResp.Header.Get("Content-Type")),
					ContentType: postResp.Header.Get("Content-Type"),
				})
			}
		}
	}

	return results
}
