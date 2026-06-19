package webshell

import "time"

type DetectionMethod string

const (
	MethodSignature DetectionMethod = "signature"
	MethodEntropy   DetectionMethod = "entropy"
	MethodBehavior  DetectionMethod = "behavioral"
	MethodNetwork   DetectionMethod = "network"
	MethodHash      DetectionMethod = "known_hash"
)

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type Language string

const (
	LangPHP     Language = "php"
	LangASP     Language = "asp"
	LangASPX    Language = "aspx"
	LangJSP     Language = "jsp"
	LangPython  Language = "python"
	LangPerl    Language = "perl"
	LangGeneric Language = "generic"
)

type Finding struct {
	FilePath          string          `json:"file_path"`
	FileName          string          `json:"file_name"`
	Language          Language        `json:"language"`
	Severity          Severity        `json:"severity"`
	Confidence        float64         `json:"confidence"`
	DetectionMethod   DetectionMethod `json:"detection_method"`
	MatchedSignatures []string        `json:"matched_signatures,omitempty"`
	EntropyScore      float64         `json:"entropy_score,omitempty"`
	MD5               string          `json:"md5,omitempty"`
	SHA256            string          `json:"sha256,omitempty"`
	FileSize          int64           `json:"file_size"`
	ModifiedAt        time.Time       `json:"modified_at"`
	Permissions       string          `json:"permissions,omitempty"`
	MIMEType          string          `json:"mime_type,omitempty"`
	MatchedHash       string          `json:"matched_hash_name,omitempty"`
	Evidence          string          `json:"evidence,omitempty"`
}

type Config struct {
	EntropyThreshold   float64
	MaxFileSize        int64
	WebRoots           []string
	UploadDirs         []string
	KnownHashDB        map[string]string
	MaxEntropyScanSize int64
	ScannerTimeout     time.Duration
}

func DefaultConfig() Config {
	return Config{
		EntropyThreshold:   5.5,
		MaxFileSize:        10 << 20,
		WebRoots:           []string{"/var/www/html", "/var/www", "/srv/www", "/usr/share/nginx/html", "C:\\inetpub\\wwwroot"},
		UploadDirs:         []string{"uploads", "files", "images", "media", "assets", "tmp", "temp", "download"},
		KnownHashDB:        nil,
		MaxEntropyScanSize: 1 << 20,
		ScannerTimeout:     30 * time.Second,
	}
}

type Result struct {
	Target    string    `json:"target"`
	Findings  []Finding `json:"findings"`
	Scanned   int       `json:"scanned_files"`
	Skipped   int       `json:"skipped_files"`
	Duration  string    `json:"duration"`
	ScannedAt time.Time `json:"scanned_at"`
}
