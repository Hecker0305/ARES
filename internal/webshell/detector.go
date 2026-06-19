package webshell

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

func ctxDone(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

type Detector struct {
	mu          sync.Mutex
	config      Config
	hashDB      map[string]string
	sigCompiled []struct {
		name     string
		re       *regexp.Regexp
		language Language
		severity Severity
		weight   int
	}
}

func NewDetector(cfg Config) *Detector {
	d := &Detector{
		config: cfg,
		hashDB: cfg.KnownHashDB,
	}
	if d.hashDB == nil {
		d.hashDB = buildHashDB()
	}
	d.compileSignatures()
	return d
}

func (d *Detector) compileSignatures() {
	for _, s := range signatures {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			logger.Warn(fmt.Sprintf("[Webshell] failed to compile signature %q: %v", s.Name, err))
			continue
		}
		d.sigCompiled = append(d.sigCompiled, struct {
			name     string
			re       *regexp.Regexp
			language Language
			severity Severity
			weight   int
		}{name: s.Name, re: re, language: s.Language, severity: s.Severity, weight: s.Weight})
	}
}

func (d *Detector) ScanFile(path string, webRoots []string, uploadDirs []string) ([]Finding, error) {
	info, err := collectFileInfo(path, webRoots, uploadDirs)
	if err != nil {
		return nil, err
	}

	if info.size > d.config.MaxFileSize {
		return nil, nil
	}

	if !isScriptExtension(info.extension) {
		return nil, nil
	}

	var findings []Finding

	hashFindings := d.checkHashes(info)
	findings = append(findings, hashFindings...)

	content, err := os.ReadFile(path)
	if err != nil {
		return findings, err
	}

	sigFindings := d.matchSignatures(info, content)
	findings = append(findings, sigFindings...)

	entropyScore, isHigh := isHighEntropyFile(content, d.config.EntropyThreshold)
	if isHigh {
		hasSig := false
		for _, f := range sigFindings {
			if f.DetectionMethod == MethodSignature {
				hasSig = true
				break
			}
		}
		confidence := 0.5
		severity := SeverityMedium
		if hasSig {
			confidence = 0.9
			severity = SeverityHigh
		}
		findings = append(findings, Finding{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        severity,
			Confidence:      confidence,
			DetectionMethod: MethodEntropy,
			EntropyScore:    entropyScore,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			Evidence:        fmt.Sprintf("Shannon entropy %.2f exceeds threshold %.1f", entropyScore, d.config.EntropyThreshold),
		})
	}

	behavFindings := checkBehavioralIndicators(info)
	findings = append(findings, behavFindings...)

	findings = d.deduplicateAndScore(findings)
	return findings, nil
}

func (d *Detector) checkHashes(info *fileInfo) []Finding {
	if entry, ok := d.hashDB[info.sha256]; ok {
		return []Finding{{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        SeverityHigh,
			Confidence:      1.0,
			DetectionMethod: MethodHash,
			MD5:             info.md5,
			SHA256:          info.sha256,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			MatchedHash:     entry,
			Evidence:        fmt.Sprintf("known webshell hash match: %s", entry),
		}}
	}
	if entry, ok := d.hashDB[info.md5]; ok {
		return []Finding{{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        SeverityHigh,
			Confidence:      0.95,
			DetectionMethod: MethodHash,
			MD5:             info.md5,
			SHA256:          info.sha256,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			MatchedHash:     entry,
			Evidence:        fmt.Sprintf("known webshell MD5 match: %s", entry),
		}}
	}
	return nil
}

func (d *Detector) matchSignatures(info *fileInfo, content []byte) []Finding {
	var findings []Finding
	contentStr := string(content)

	for _, sig := range d.sigCompiled {
		if sig.re.MatchString(contentStr) {
			findings = append(findings, Finding{
				FilePath:          info.path,
				FileName:          info.name,
				Language:          sig.language,
				Severity:          sig.severity,
				Confidence:        float64(sig.weight) / 100.0,
				DetectionMethod:   MethodSignature,
				MatchedSignatures: []string{sig.name},
				FileSize:          info.size,
				ModifiedAt:        info.modTime,
				Evidence:          fmt.Sprintf("matched signature: %s", sig.name),
			})
		}
	}

	return findings
}

func (d *Detector) deduplicateAndScore(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding

	for _, f := range findings {
		key := fmt.Sprintf("%s|%s", f.FilePath, f.DetectionMethod)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}

	for i := range result {
		if result[i].Confidence > 1.0 {
			result[i].Confidence = 1.0
		}
	}

	return result
}

func (d *Detector) ScanWebRoot(ctx context.Context, webRoot string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:    webRoot,
		ScannedAt: time.Now(),
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if ctxDone(ctx) {
			return ctx.Err()
		}
		if info.IsDir() {
			skipDirs := map[string]bool{".git": true, ".svn": true, "node_modules": true, ".cache": true}
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !isScriptExtension(ext) {
			result.Skipped++
			return nil
		}
		findings, err := d.ScanFile(path, []string{webRoot}, d.config.UploadDirs)
		if err != nil {
			logger.Warn(fmt.Sprintf("[Webshell] scan error %s: %v", path, err))
			result.Skipped++
			return nil
		}
		result.Scanned++
		result.Findings = append(result.Findings, findings...)
		return nil
	}

	filepath.Walk(webRoot, walkFn)
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	if ctxDone(ctx) {
		return result, ctx.Err()
	}
	return result, nil
}

func (d *Detector) ScanUploadDir(ctx context.Context, dir string, webRoots []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:    dir,
		ScannedAt: time.Now(),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if ctxDone(ctx) {
			break
		}
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !isScriptExtension(ext) {
			result.Skipped++
			continue
		}
		findings, err := d.ScanFile(path, webRoots, d.config.UploadDirs)
		if err != nil {
			logger.Warn(fmt.Sprintf("[Webshell] upload scan error %s: %v", path, err))
			result.Skipped++
			continue
		}
		result.Scanned++
		result.Findings = append(result.Findings, findings...)
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	if ctxDone(ctx) {
		return result, ctx.Err()
	}
	return result, nil
}

func (d *Detector) ScanNetwork(ctx context.Context, baseURL string, paths []string) []networkDetectResult {
	return checkStaticFilePostResponse(ctx, baseURL, paths, d.config.ScannerTimeout)
}

func (d *Detector) DetectFromBytes(name string, content []byte, webRoots []string, uploadDirs []string) ([]Finding, error) {
	tmpDir, err := os.MkdirTemp("", "webshell-scan-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, name)
	if err := os.WriteFile(tmpPath, content, 0644); err != nil {
		return nil, err
	}

	return d.ScanFile(tmpPath, webRoots, uploadDirs)
}

type Scanner struct {
	detector *Detector
}

func NewScanner(cfg Config) *Scanner {
	return &Scanner{detector: NewDetector(cfg)}
}

func (s *Scanner) ScanReader(name string, r *bufio.Reader, size int64, webRoots []string, uploadDirs []string) ([]Finding, error) {
	var buf bytes.Buffer
	if size > 0 && size < int64(10<<20) {
		buf.Grow(int(size))
	}
	written, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	_ = written
	return s.detector.DetectFromBytes(name, buf.Bytes(), webRoots, uploadDirs)
}
