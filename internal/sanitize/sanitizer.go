package sanitize

import (
	"regexp"
)

type Sanitizer struct {
	patterns []sanitizerPattern
}

type sanitizerPattern struct {
	name    string
	pattern *regexp.Regexp
	action  string
}

type SanitizeResult struct {
	Sanitized string
	Flags     []string
	Blocked   bool
}

var unixPathPattern = regexp.MustCompile(`/[a-zA-Z0-9_/.-]{6,}`)

var windowsPathPattern = regexp.MustCompile(`(?i)[A-Z]:\\[a-zA-Z0-9_\\.-]{3,}`)

var urlEncodedPathPattern = regexp.MustCompile(`(?:%2[Ff]|[\\/])[a-zA-Z0-9_.%-]{6,}`)

type TemplateSanitizer struct{}
