package agent

import "time"

// AddFindingRaw implements tools.findingAdder — avoids circular imports.
func (sc *ScanContext) AddFindingRaw(
	id, title, severity, endpoint, description, impact, pocCode,
	extractionProof, evidencePath, mitreTactic, mitreTechnique string,
	cvss, confidence float64,
	pocSteps []string,
	confirmed bool,
	ts time.Time,
) {
	f := Finding{
		ID:              id,
		Title:           title,
		Severity:        Severity(severity),
		Endpoint:        endpoint,
		Description:     description,
		Impact:          impact,
		CVSSScore:       cvss,
		PoCSteps:        pocSteps,
		PoCCode:         pocCode,
		ExtractionProof: extractionProof,
		EvidencePath:    evidencePath,
		MITRETactic:     mitreTactic,
		MITRETechnique:  mitreTechnique,
		Confidence:      confidence,
		Confirmed:       confirmed,
		Timestamp:       ts,
	}
	sc.AddFinding(f)
}

// Report interface methods

func (sc *ScanContext) GetTarget() string { return sc.Target }

func (f Finding) GetTitle() string       { return f.Title }
func (f Finding) GetSeverity() string    { return string(f.Severity) }
func (f Finding) GetEndpoint() string    { return f.Endpoint }
func (f Finding) GetDescription() string { return f.Description }
