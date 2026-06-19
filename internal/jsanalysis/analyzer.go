package jsanalysis

import "time"

type Endpoint struct {
	Method string
	Path   string
}

type AnalysisResult struct {
	URL          string
	Endpoints    []string
	APIEndpoints []Endpoint
	Secrets      []string
	TechStack    []string
}

type Analyzer struct {
	timeout time.Duration
}

func NewAnalyzer(timeout time.Duration) *Analyzer {
	return &Analyzer{timeout: timeout}
}

func (a *Analyzer) ScanURLs(urls []string) AnalysisResult {
	return AnalysisResult{
		URL:          "",
		APIEndpoints: []Endpoint{},
	}
}
