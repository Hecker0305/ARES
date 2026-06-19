package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

type CommandSpec struct {
	Binary string
	Args   []string
}

type CommandValidationResult struct {
	Binary      string
	Args        []string
	Err         error
	Hash        string
	HashPath    string
	validatedAt time.Time
}

type AllowedBinary struct {
	Path       string
	SHA256Hash string
	AllowArgs  bool
}

var (
	allowedBinariesMu sync.RWMutex
	allowedBinaries   = defaultAllowedBinaries()
)

// StrictVerification rejects binaries without pre-configured SHA256 hashes.
// When false (default), hashes are computed at first use and cached.
// When true, binaries without hashes in the allowlist are denied.
var StrictVerification bool

func init() {
	loadPersistedHashes()
}

const hashStoreFile = "binary_hashes.json"

func hashStoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Join(home, ".ares")
}

func hashStorePath() string {
	return filepath.Join(hashStoreDir(), hashStoreFile)
}

func loadPersistedHashes() {
	path := hashStorePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stored map[string]string
	if err := json.Unmarshal(data, &stored); err != nil {
		return
	}
	allowedBinariesMu.Lock()
	defer allowedBinariesMu.Unlock()
	for name, hash := range stored {
		if ab, ok := allowedBinaries[name]; ok {
			if ab.SHA256Hash == "" {
				ab.SHA256Hash = hash
				allowedBinaries[name] = ab
			}
		}
	}
}

func persistHash(binaryName, hashStr string) {
	path := hashStorePath()
	dir := hashStoreDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	allowedBinariesMu.RLock()
	all := make(map[string]string, len(allowedBinaries))
	for name, ab := range allowedBinaries {
		if ab.SHA256Hash != "" {
			all[name] = ab.SHA256Hash
		}
	}
	allowedBinariesMu.RUnlock()
	all[binaryName] = hashStr
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0600)
}

func defaultAllowedBinaries() map[string]AllowedBinary {
	if runtime.GOOS == "windows" {
		return map[string]AllowedBinary{
			"nmap":       {Path: `C:\Program Files (x86)\Nmap\nmap.exe`, SHA256Hash: "", AllowArgs: true},
			"curl":       {Path: `C:\Windows\System32\curl.exe`, SHA256Hash: "", AllowArgs: true},
			"find":       {Path: `C:\Windows\System32\find.exe`, SHA256Hash: "", AllowArgs: true},
			"ping":       {Path: `C:\Windows\System32\ping.exe`, SHA256Hash: "", AllowArgs: true},
			"nslookup":   {Path: `C:\Windows\System32\nslookup.exe`, SHA256Hash: "", AllowArgs: true},
			"systeminfo": {Path: `C:\Windows\System32\systeminfo.exe`, SHA256Hash: "", AllowArgs: true},
		}
	}
	return map[string]AllowedBinary{
		"nmap":         {Path: "/usr/bin/nmap", SHA256Hash: "", AllowArgs: true},
		"nuclei":       {Path: "/usr/bin/nuclei", SHA256Hash: "", AllowArgs: true},
		"curl":         {Path: "/usr/bin/curl", SHA256Hash: "", AllowArgs: true},
		"dig":          {Path: "/usr/bin/dig", SHA256Hash: "", AllowArgs: true},
		"host":         {Path: "/usr/bin/host", SHA256Hash: "", AllowArgs: true},
		"ping":         {Path: "/usr/bin/ping", SHA256Hash: "", AllowArgs: true},
		"subfinder":    {Path: "/usr/bin/subfinder", SHA256Hash: "", AllowArgs: true},
		"httpx":        {Path: "/usr/bin/httpx", SHA256Hash: "", AllowArgs: true},
		"whatweb":      {Path: "/usr/bin/whatweb", SHA256Hash: "", AllowArgs: true},
		"wafw00f":      {Path: "/usr/bin/wafw00f", SHA256Hash: "", AllowArgs: true},
		"katana":       {Path: "/usr/bin/katana", SHA256Hash: "", AllowArgs: true},
		"arjun":        {Path: "/usr/bin/arjun", SHA256Hash: "", AllowArgs: true},
		"gobuster":     {Path: "/usr/bin/gobuster", SHA256Hash: "", AllowArgs: true},
		"ffuf":         {Path: "/usr/bin/ffuf", SHA256Hash: "", AllowArgs: true},
		"python3":      {Path: "/usr/bin/python3", SHA256Hash: "", AllowArgs: true},
		"python":       {Path: "/usr/bin/python", SHA256Hash: "", AllowArgs: true},
		"nikto":        {Path: "/usr/bin/nikto", SHA256Hash: "", AllowArgs: true},
		"sqlmap":       {Path: "/usr/bin/sqlmap", SHA256Hash: "", AllowArgs: true},
		"dalfox":       {Path: "/usr/bin/dalfox", SHA256Hash: "", AllowArgs: true},
		"recon-ng":     {Path: "/usr/bin/recon-ng", SHA256Hash: "", AllowArgs: true},
		"theHarvester": {Path: "/usr/bin/theHarvester", SHA256Hash: "", AllowArgs: true},
		"amass":        {Path: "/usr/bin/amass", SHA256Hash: "", AllowArgs: true},
		"xsser":        {Path: "/usr/bin/xsser", SHA256Hash: "", AllowArgs: true},
		"linpeas":      {Path: "/usr/bin/linpeas.sh", SHA256Hash: "", AllowArgs: true},
	}
}

func getAllowedBinary(name string) (AllowedBinary, bool) {
	allowedBinariesMu.RLock()
	defer allowedBinariesMu.RUnlock()
	b, ok := allowedBinaries[name]
	return b, ok
}

func ValidateCommand(spec CommandSpec) CommandValidationResult {
	if spec.Binary == "" {
		return CommandValidationResult{Err: &ValidationError{Message: "empty binary name"}}
	}

	binaryName := strings.ToLower(strings.TrimSpace(spec.Binary))

	if strings.Contains(binaryName, "/") || strings.Contains(binaryName, "\\") {
		return CommandValidationResult{Err: &ValidationError{Message: "relative or absolute path not allowed, use binary name only"}}
	}

	allowed, exists := getAllowedBinary(binaryName)
	if !exists {
		return CommandValidationResult{Err: &ValidationError{Message: fmt.Sprintf("binary not in allowlist: %s", binaryName)}}
	}

	binaryPath, err := exec.LookPath(allowed.Path)
	if err != nil {
		binaryPath, err = exec.LookPath(binaryName)
		if err != nil {
			return CommandValidationResult{Err: &ValidationError{Message: fmt.Sprintf("binary not found: %s", binaryName)}}
		}
	}

	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return CommandValidationResult{Err: &ValidationError{Message: "failed to resolve binary path"}}
	}

	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(binaryPath, "C:\\") && !strings.HasPrefix(binaryPath, "D:\\") {
			return CommandValidationResult{Err: &ValidationError{Message: "binary must be in system path"}}
		}
	} else if !strings.HasPrefix(binaryPath, "/") {
		return CommandValidationResult{Err: &ValidationError{Message: "binary must be an absolute path"}}
	}

	info, err := os.Stat(binaryPath)
	if err != nil {
		return CommandValidationResult{Err: &ValidationError{Message: "binary not accessible"}}
	}

	mode := info.Mode()
	if mode.IsDir() {
		return CommandValidationResult{Err: &ValidationError{Message: "path is a directory, not a binary"}}
	}

	if runtime.GOOS != "windows" {
		if mode&0111 == 0 {
			data, err := os.ReadFile(binaryPath)
			if err != nil || !isShebangScript(data) {
				return CommandValidationResult{Err: &ValidationError{Message: "binary is not executable"}}
			}
		}
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return CommandValidationResult{Err: &ValidationError{Message: fmt.Sprintf("cannot read binary %q: %v", binaryName, err)}}
	}
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	if allowed.SHA256Hash == "" {
		if StrictVerification {
			return CommandValidationResult{
				Err: &ValidationError{Message: fmt.Sprintf("binary %q has no SHA256 hash — set StrictVerification=false to auto-hash, or pin hashes via InitAllowedBinaries()", binaryName)},
			}
		}
		allowedBinariesMu.Lock()
		ab := allowedBinaries[binaryName]
		ab.SHA256Hash = hashStr
		allowedBinaries[binaryName] = ab
		allowedBinariesMu.Unlock()
		persistHash(binaryName, hashStr)
	} else if !strings.EqualFold(hashStr, allowed.SHA256Hash) {
		return CommandValidationResult{
			Err: &ValidationError{Message: fmt.Sprintf("binary %q hash mismatch: expected %s, got %s", binaryName, allowed.SHA256Hash, hashStr)},
		}
	}

	if !allowed.AllowArgs && len(spec.Args) > 0 {
		return CommandValidationResult{Err: &ValidationError{Message: fmt.Sprintf("binary %s does not allow arguments", binaryName)}}
	}

	for _, arg := range spec.Args {
		if err := validateArg(arg); err != nil {
			return CommandValidationResult{Err: &ValidationError{Message: fmt.Sprintf("invalid argument %q: %v", arg, err)}}
		}
	}

	return CommandValidationResult{
		Binary:      binaryPath,
		Args:        spec.Args,
		Hash:        hashStr,
		HashPath:    binaryPath,
		validatedAt: time.Now(),
	}
}

func isShebangScript(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return data[0] == '#' && data[1] == '!'
}

func validateArg(arg string) error {
	if arg == "" {
		return &ValidationError{Message: "empty argument"}
	}

	for _, r := range arg {
		if r < 32 && r != '\t' {
			return &ValidationError{Message: "control character in argument"}
		}
	}

	if strings.ContainsAny(arg, "|;&$`'\"(){}[]<>!*?\\") {
		return &ValidationError{Message: "shell metacharacter in argument"}
	}

	if strings.Contains(arg, "..") {
		if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
			return &ValidationError{Message: "path traversal in argument"}
		}
	}

	return nil
}

var promptInjectionPatterns = []struct {
	pattern  string
	category string
}{
	{"ignore previous instructions", "instruction_override"},
	{"ignore all instructions", "instruction_override"},
	{"ignore all previous", "instruction_override"},
	{"system prompt:", "system_prompt_leak"},
	{"you are now", "role_override"},
	{"you are an", "role_override"},
	{"from now on", "role_override"},
	{"consider yourself", "role_override"},
	{"pretend you are", "role_override"},
	{"act as", "role_override"},
	{"forget everything", "memory_override"},
	{"disregard all", "instruction_override"},
	{"new instructions:", "instruction_override"},
	{"override:", "instruction_override"},
	{"override mode", "instruction_override"},
	{"token: ", "token_leak"},
	{"secret: ", "secret_leak"},
	{"password: ", "secret_leak"},
	{"api_key:", "secret_leak"},
	{"api_key =", "secret_leak"},
}

type SanitizationResult struct {
	Sanitized string   `json:"sanitized"`
	Flags     []string `json:"flags"`
	Blocked   bool     `json:"blocked"`
}

var semanticLLMPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<!--.*?IGNORE PREVIOUS.*?-->`),
	regexp.MustCompile(`(?is)<!--.*?report\s+zero\s+findings.*?-->`),
	regexp.MustCompile(`(?is)<!--.*?do\s+not\s+(report|flag|alert).*?-->`),
	regexp.MustCompile(`(?is)\[SYSTEM\].*?:.*?(?:execute|run|curl|wget|nc)\b`),
	regexp.MustCompile(`(?is)X-(?:Command|Instruction|Override|Inject):\s*`),
	regexp.MustCompile(`(?i)\bmaintenance\s*mode\b.*?\bexecute\b`),
	regexp.MustCompile(`(?i)(?:curl|wget|nc|ncat)\s+.*\?(?:data|secret|key|token|password)=`),
}

func SanitizeLLMOutput(output string) SanitizationResult {
	var flags []string
	lower := strings.ToLower(output)
	for _, p := range promptInjectionPatterns {
		if strings.Contains(lower, p.pattern) {
			flags = append(flags, p.category+":"+p.pattern)
		}
	}
	for _, re := range semanticLLMPatterns {
		if re.MatchString(output) {
			flags = append(flags, "semantic_injection:"+re.String())
		}
	}
	if IsUnicodeHomoglyph(output) {
		flags = append(flags, "unicode_homoglyph_detected")
	}
	blocked := len(flags) > 2 || (len(flags) > 0 && strings.Contains(output, "IGNORE PREVIOUS"))
	return SanitizationResult{
		Sanitized: output,
		Flags:     flags,
		Blocked:   blocked,
	}
}

func SanitizeInput(input string) string {
	var result strings.Builder
	for _, r := range input {
		if r < 32 && r != '\n' && r != '\t' && r != '\r' {
			continue
		}
		if r == 0 {
			continue
		}
		result.WriteRune(r)
	}
	return strings.TrimSpace(result.String())
}

func SanitizeFilename(filename string) (string, error) {
	if filename == "" {
		return "", &ValidationError{Message: "empty filename"}
	}

	invalidChars := []string{"/", "\\", "..", "\x00", "\n", "\r"}
	for _, char := range invalidChars {
		if strings.Contains(filename, char) {
			return "", &ValidationError{Message: "invalid characters in filename"}
		}
	}

	clean := strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r == '_' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			return r
		}
		return '_'
	}, filename)

	return clean, nil
}

func ValidateTarget(target string) error {
	if target == "" {
		return &ValidationError{Message: "empty target"}
	}

	target = strings.TrimSpace(target)
	target = strings.ToLower(target)

	// Try parsing as IP first
	if ip := net.ParseIP(target); ip != nil {
		if isPrivateIP(ip) {
			return &ValidationError{Message: "private IP address not allowed"}
		}
		return nil
	}

	// Try parsing as CIDR
	if _, cidr, err := net.ParseCIDR(target); err == nil {
		_, bits := cidr.Mask.Size()
		if bits == 32 || bits == 128 {
			if isPrivateIP(cidr.IP) {
				return &ValidationError{Message: "private IP range not allowed"}
			}
		}
		return nil
	}

	// Fallback: string prefix check for hostnames that start with IP-like patterns
	privateIPRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.",
		"192.168.",
		"127.",
	}

	for _, range_ := range privateIPRanges {
		if strings.HasPrefix(target, range_) {
			return &ValidationError{Message: "private IP address not allowed"}
		}
	}

	return nil
}

var privateBlocks = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("fe80::/10"),
	mustParseCIDR("100.64.0.0/10"),
}

func isPrivateIP(ip net.IP) bool {
	// Allow configuration of private IP ranges via environment variable
	overrideRanges := os.Getenv("ARES_PRIVATE_IP_RANGES")
	if overrideRanges != "" {
		customBlocks := parseCIDRRanges(overrideRanges)
		if len(customBlocks) > 0 {
			for _, b := range customBlocks {
				if b.Contains(ip) {
					return true
				}
			}
		}
	}

	for _, b := range privateBlocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRRanges(ranges string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range strings.Split(ranges, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil {
				nets = append(nets, n)
			}
		}
	}
	return nets
}

func mustParseCIDR(s string) *net.IPNet {
	_, c, err := net.ParseCIDR(s)
	if err != nil {
		logger.Error("invalid CIDR configuration", logger.Fields{"cidr": s, "error": err})
		return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	return c
}

func SecureEnvVars() map[string]string {
	secureVars := make(map[string]string)
	allowedVars := []string{
		"HOME", "PATH", "PWD", "SHELL", "TERM",
		"USER", "USERNAME",
	}

	for _, key := range allowedVars {
		if val := os.Getenv(key); val != "" {
			secureVars[key] = val
		}
	}

	return secureVars
}

func ValidateHostForSSRF(host string) error {
	if host == "" {
		return &ValidationError{Message: "empty host"}
	}
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "169.254.169.254" || lower == "metadata.google.internal" ||
		lower == "metadata.google.internal." || strings.HasSuffix(lower, ".internal") {
		return &ValidationError{Message: "metadata endpoint blocked"}
	}
	if strings.HasPrefix(lower, "100.100.") || strings.HasPrefix(lower, "100.64.") {
		return &ValidationError{Message: "carrier-grade NAT range blocked"}
	}
	if ip := net.ParseIP(lower); ip != nil {
		if isPrivateIP(ip) || ip.IsLoopback() {
			return &ValidationError{Message: "private or loopback IP not allowed"}
		}
	}
	return nil
}

func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return &ValidationError{Message: "empty URL"}
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return &ValidationError{Message: fmt.Sprintf("invalid URL: %v", err)}
	}

	blockedSchemes := map[string]bool{
		"file": true, "gopher": true, "javascript": true,
		"data": true, "ftp": true, "telnet": true,
		"dict": true, "ldap": true, "smb": true,
	}
	if blockedSchemes[strings.ToLower(u.Scheme)] {
		return &ValidationError{Message: fmt.Sprintf("blocked scheme: %s", u.Scheme)}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &ValidationError{Message: fmt.Sprintf("unsupported scheme: %s", u.Scheme)}
	}
	host := u.Hostname()
	if err := ValidateHostForSSRF(host); err != nil {
		return err
	}
	return nil
}

func ValidateShellCommand(cmd string) error {
	if cmd == "" {
		return &ValidationError{Message: "empty command"}
	}
	if len(cmd) > 4096 {
		return &ValidationError{Message: "command too long"}
	}
	disallowed := []string{";", "|", "`", "$(", "${", "\n", "\r"}
	for _, d := range disallowed {
		if strings.Contains(cmd, d) {
			return &ValidationError{Message: fmt.Sprintf("shell metacharacter in command: %q", d)}
		}
	}
	return nil
}

func ParseCommandToArgs(cmd string) (string, []string, error) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", nil, &ValidationError{Message: "empty command"}
	}
	return parts[0], parts[1:], nil
}

func ValidateFileReadScope(path string) error {
	if path == "" {
		return &ValidationError{Message: "empty path"}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return &ValidationError{Message: fmt.Sprintf("cannot resolve path: %v", err)}
	}
	abs = filepath.Clean(abs)
	sysPaths := []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var"}
	for _, sp := range sysPaths {
		if abs == sp || strings.HasPrefix(abs, sp+"/") {
			return &ValidationError{Message: fmt.Sprintf("access denied: %s is a system path", sp)}
		}
	}
	return nil
}

func ValidateReadPath(path string) (string, error) {
	if path == "" {
		return "", &ValidationError{Message: "empty path"}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", &ValidationError{Message: fmt.Sprintf("cannot resolve path: %v", err)}
	}
	abs = filepath.Clean(abs)
	if strings.Contains(abs, "..") {
		return "", &ValidationError{Message: "path traversal detected"}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", &ValidationError{Message: fmt.Sprintf("path not accessible: %v", err)}
	}
	if info.IsDir() {
		return "", &ValidationError{Message: "path is a directory, not a file"}
	}
	return abs, nil
}

// SecureRandIntn returns a cryptographically secure random integer in the range [0, n).
func SecureRandIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("n must be positive")
	}
	result, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("crypto/rand failed: %w", err)
	}
	return int(result.Int64()), nil
}
