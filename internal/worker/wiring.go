package worker

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ares/engine/internal/agent"
	"github.com/ares/engine/internal/analyzer"
	"github.com/ares/engine/internal/apiattacks"
	"github.com/ares/engine/internal/apidiscovery"
	"github.com/ares/engine/internal/authflow"
	"github.com/ares/engine/internal/autorecon"
	"github.com/ares/engine/internal/bizlogic"
	"github.com/ares/engine/internal/broffensive"
	"github.com/ares/engine/internal/cloudscanner"
	"github.com/ares/engine/internal/container"
	"github.com/ares/engine/internal/deserial"
	"github.com/ares/engine/internal/fuzz"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/nosqli"
	"github.com/ares/engine/internal/oauth"
	"github.com/ares/engine/internal/protopollution"
	"github.com/ares/engine/internal/race"
	"github.com/ares/engine/internal/recon"
	"github.com/ares/engine/internal/smuggling"
	"github.com/ares/engine/internal/ssti"
	"github.com/ares/engine/internal/traversal"
	"github.com/ares/engine/internal/webexploit"
	"github.com/ares/engine/internal/browser"
	"github.com/ares/engine/internal/webshell"
	"github.com/ares/engine/internal/xxe"
)

type SpecializedScannerResults struct {
	Findings      []agent.Finding
	DiscoveredEPs []string
	LiveHosts     []string
	TechStack     []string
	Errors        []error
}

func RunSpecializedScanners(ctx context.Context, target string, oobDomain string) *SpecializedScannerResults {
	res := &SpecializedScannerResults{
		Findings:      make([]agent.Finding, 0),
		DiscoveredEPs: make([]string, 0),
		LiveHosts:     make([]string, 0),
		TechStack:     make([]string, 0),
		Errors:        make([]error, 0),
	}

	scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	done := make(chan struct{}, 1)
	go func() {
		runAttackEngines(scanCtx, target, oobDomain, res)
		runScanningEngines(scanCtx, target, res)
		runAnalysisEngines(scanCtx, target, res)
		runWebshellDetection(scanCtx, target, res)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-scanCtx.Done():
		res.Errors = append(res.Errors, scanCtx.Err())
	}

	return res
}

func toAgentFinding(id, title, severity, endpoint, description, payload, evidence string) agent.Finding {
	return agent.Finding{
		ID:              id,
		Title:           title,
		Severity:        agent.Severity(severity),
		Endpoint:        endpoint,
		Description:     description,
		PoCCode:         payload,
		ExtractionProof: evidence,
		Confirmed:       true,
		Timestamp:       time.Now(),
	}
}

func runAttackEngines(ctx context.Context, target, oobDomain string, res *SpecializedScannerResults) {
	apiEng := apiattacks.New()
	baseURL := target

	idorResults := apiEng.TestIDOR(ctx, baseURL, nil)
	for _, r := range idorResults {
		if !r.Vulnerable {
			continue
		}
		res.Findings = append(res.Findings, toAgentFinding(
			fmt.Sprintf("APIATTACK-IDOR-%d", len(res.Findings)),
			"IDOR: "+r.Endpoint,
			r.Severity, target, r.Test, "", r.Evidence,
		))
	}

	maResults := apiEng.TestMassAssignment(ctx, baseURL, nil)
	for _, r := range maResults {
		if !r.Vulnerable {
			continue
		}
		res.Findings = append(res.Findings, toAgentFinding(
			fmt.Sprintf("APIATTACK-MA-%d", len(res.Findings)),
			"Mass Assignment: "+r.Endpoint,
			r.Severity, target, r.Test, "", r.Evidence,
		))
	}

	rlResults := apiEng.TestRateLimitBypass(ctx, baseURL, "", false)
	for _, r := range rlResults {
		if !r.Vulnerable {
			continue
		}
		res.Findings = append(res.Findings, toAgentFinding(
			fmt.Sprintf("APIATTACK-RL-%d", len(res.Findings)),
			"Rate Limit Bypass: "+r.Endpoint,
			r.Severity, target, r.Test, "", r.Evidence,
		))
	}

	disc := apidiscovery.NewDiscoverer(target, 30*time.Second)
	discResult := disc.DiscoverAll()
	if discResult != nil {
		for _, ep := range discResult.Endpoints {
			res.DiscoveredEPs = append(res.DiscoveredEPs, ep.Method+" "+ep.Path)
		}
		for _, au := range discResult.AuthTypes {
			res.TechStack = append(res.TechStack, "auth:"+string(au))
		}
		if discResult.GraphQLDetected {
			res.TechStack = append(res.TechStack, "graphql")
		}
		if discResult.GRPCDetected {
			res.TechStack = append(res.TechStack, "grpc")
		}
	}

	desEng := deserial.NewEngine(oobDomain)
	desFindings, err := desEng.TestAll(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] Deserialization test failed: %v", err))
	} else {
		for _, f := range desFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("DESERIAL-%d", len(res.Findings)),
				"Deserialization: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	noEng := nosqli.NewEngine()
	noFindings, err := noEng.TestAll(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] NoSQL injection test failed: %v", err))
	} else {
		for _, f := range noFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("NOSQLI-%d", len(res.Findings)),
				"NoSQL Injection: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	sstiEng := ssti.NewEngine(oobDomain)
	sstiFindings, err := sstiEng.TestAll(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] SSTI test failed: %v", err))
	} else {
		for _, f := range sstiFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("SSTI-%d", len(res.Findings)),
				"SSTI: "+f.Engine,
				f.Severity, f.URL, f.Engine, f.Payload, f.Evidence,
			))
		}
	}

	smugEng := smuggling.New()
	for _, dt := range []smuggling.DesyncType{smuggling.CLTE, smuggling.TECL, smuggling.TETE} {
		smugResult, err := smugEng.Test(ctx, target, dt)
		if err != nil {
			logger.Error(fmt.Sprintf("[Worker] Smuggling test failed: %v", err))
			continue
		}
		if smugResult != nil && smugResult.Vulnerable {
			payloadStr := ""
			if len(smugResult.Payloads) > 0 {
				payloadStr = smugResult.Payloads[0].Attack
			}
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("SMUGGLE-%d", len(res.Findings)),
				"HTTP Request Smuggling: "+dt.String(),
				"CRITICAL", target, dt.String(), payloadStr, smugResult.Evidence,
			))
		}
	}

	travEng := traversal.NewEngine(oobDomain)
	travFindings, err := travEng.TestAll(target, "file")
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] Path traversal test failed: %v", err))
	} else {
		for _, f := range travFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("TRAVERSAL-%d", len(res.Findings)),
				"Path Traversal: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	webEng := webexploit.New(10)
	crawlResults := webEng.Crawl(ctx, target, 2)
	for _, cr := range crawlResults {
		res.DiscoveredEPs = append(res.DiscoveredEPs, cr.Endpoints...)
		res.TechStack = append(res.TechStack, cr.Tech...)
	}

	xxeEng := xxe.NewEngine(oobDomain)
	xxeFindings, err := xxeEng.TestAll(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] XXE test failed: %v", err))
	} else {
		for _, f := range xxeFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("XXE-%d", len(res.Findings)),
				"XXE: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	oauthEng := oauth.NewEngine(oobDomain)
	oauthFindings, err := oauthEng.TestAll(target, target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] OAuth test failed: %v", err))
	} else {
		for _, f := range oauthFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("OAUTH-%d", len(res.Findings)),
				"OAuth: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	protoEng := protopollution.NewEngine(oobDomain)
	protoFindings, err := protoEng.TestAll(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] Prototype pollution test failed: %v", err))
	} else {
		for _, f := range protoFindings {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("PROTO-%d", len(res.Findings)),
				"Prototype Pollution: "+f.Type,
				f.Severity, f.URL, f.Type, f.Payload, f.Evidence,
			))
		}
	}

	raceEng := race.New()
	for _, cond := range []race.Condition{race.TOCTOU, race.ConcurrentWrite, race.AuthBypassRace} {
		raceResult, err := raceEng.Run(ctx, race.Config{
			TargetURL: target,
			Condition: cond,
		})
		if err != nil {
			logger.Error(fmt.Sprintf("[Worker] Race condition test failed: %v", err))
			continue
		}
		if raceResult != nil && raceResult.Vulnerable {
			evidence := raceResult.Summary
			if len(raceResult.Evidence) > 0 {
				evidence = raceResult.Evidence[0].Delta
			}
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("RACE-%d", len(res.Findings)),
				"Race Condition: "+cond.String(),
				"HIGH", target, cond.String(), "", evidence,
			))
		}
	}

	runDOMXSSScan(ctx, target, res)
}

func runDOMXSSScan(ctx context.Context, target string, res *SpecializedScannerResults) {
	if !isRemoteTarget(target) {
		return
	}
	br, err := browser.NewChromeBrowser(20 * time.Second)
	if err != nil {
		logger.Warn(fmt.Sprintf("[Worker] DOM XSS scan failed to init browser: %v", err))
		return
	}
	defer br.Close()

	params := []string{"q", "s", "search", "query", "id", "page", "url", "redirect", "next", "return"}
	for _, param := range params {
		if ctx.Err() != nil {
			return
		}
		results, err := br.ScanDOMXSS(target, param)
		if err != nil {
			continue
		}
		for _, r := range results {
			if !r.Executed && r.Confidence < 0.5 {
				continue
			}
			sev := "HIGH"
			if r.Executed {
				sev = "CRITICAL"
			}
			evidence := fmt.Sprintf("Probe: %s\nPayload: %s\nParam: %s", r.ProbeName, r.Payload, param)
			if r.Reflected != "" {
				evidence += "\nReflected: " + r.Reflected
			}
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("DOMXSS-%d", len(res.Findings)),
				fmt.Sprintf("DOM XSS in %s via %s", param, r.ProbeName),
				sev, r.URL, r.Payload, evidence, "",
			))
		}
	}
}

func isRemoteTarget(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

func runScanningEngines(ctx context.Context, target string, res *SpecializedScannerResults) {
	if !isRemoteTarget(target) {
		cloudFindings, err := cloudscanner.ScanDirectory(target)
		if err != nil {
			logger.Error(fmt.Sprintf("[Worker] Cloud scanner failed: %v", err))
		} else {
			for _, f := range cloudFindings {
				res.Findings = append(res.Findings, toAgentFinding(
					fmt.Sprintf("CLOUD-%d", len(res.Findings)),
					"Cloud Misconfiguration: "+f.Description,
					string(f.Severity), f.File, f.Description, "", f.Remediation,
				))
			}
		}
	}

	domain := target
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		domain = parsed.Hostname()
	}

	subEnum, err := recon.NewSubdomainEnum(domain)
	if err == nil {
		subResult, err := subEnum.Enumerate(ctx)
		if err != nil {
			logger.Error(fmt.Sprintf("[Worker] Subdomain enumeration failed: %v", err))
		} else if subResult != nil {
			for _, sub := range subResult.Subdomains {
				res.DiscoveredEPs = append(res.DiscoveredEPs, sub)
			}
		}
	}

	httpProbe := recon.NewHTTPProbe()
	probeResults := httpProbe.Probe(ctx, []string{target})
	for _, pr := range probeResults {
		if pr.URL != "" {
			res.DiscoveredEPs = append(res.DiscoveredEPs, pr.URL)
		}
	}

	portScanner, err := recon.NewPortScanner(domain)
	if err == nil {
		ports, err := portScanner.Scan(ctx)
		if err != nil {
			logger.Error(fmt.Sprintf("[Worker] Port scan failed: %v", err))
		} else {
			for _, p := range ports {
				if p.State == "open" {
					res.DiscoveredEPs = append(res.DiscoveredEPs, fmt.Sprintf("%s:%d", domain, p.Number))
				}
			}
		}
	}

	if !isRemoteTarget(target) {
		contEng := container.New()
		contResults := contEng.RunAll(ctx)
		for _, cr := range contResults {
			if cr.Successful {
				res.Findings = append(res.Findings, toAgentFinding(
					fmt.Sprintf("CONTAINER-%d", len(res.Findings)),
					"Container Escape: "+cr.Type.String(),
					"CRITICAL", target, cr.Description, cr.Command, cr.Output,
				))
			}
		}
	}

	fuzzEng := fuzz.NewAdaptiveFuzzer(fuzz.FuzzConfig{
		Concurrency:  5,
		Timeout:      30,
		AdaptiveMode: true,
		WAFDetection: true,
	})
	fuzzResults := fuzzEng.Run(ctx, target, []string{
		"../../../../etc/passwd",
		"<script>alert(1)</script>",
		"' OR '1'='1",
	})
	for _, fr := range fuzzResults {
		if fr.Success {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("FUZZ-%d", len(res.Findings)),
				"Fuzzing Hit",
				"HIGH", fr.URL, fr.Payload, fr.Payload, fr.Response,
			))
		}
	}

	autoEng := autorecon.New()
	corrResult, err := autoEng.Correlate(context.Background(), target)
	if err == nil && corrResult != nil {
		for _, tf := range corrResult.TechStack {
			res.TechStack = append(res.TechStack, tf.Technology)
		}
		for _, a := range corrResult.Assets {
			res.DiscoveredEPs = append(res.DiscoveredEPs, a.URL)
		}
	}
}

func runAnalysisEngines(ctx context.Context, target string, res *SpecializedScannerResults) {
	jsResult, err := analyzer.AnalyzeURL(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] JS analysis failed: %v", err))
	} else if jsResult != nil {
		res.DiscoveredEPs = append(res.DiscoveredEPs, jsResult.Endpoints...)
		for _, sec := range jsResult.Secrets {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("JS-SECRET-%d", len(res.Findings)),
				"Secret in JS: "+sec.Type,
				"HIGH", target, sec.Type, sec.Value, sec.Context,
			))
		}
		if len(jsResult.GraphQLOps) > 0 {
			res.TechStack = append(res.TechStack, "graphql")
		}
	}

	authFlow, err := authflow.DetectAuthFlow(target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] Auth flow detection failed: %v", err))
	} else if authFlow != nil {
		for _, v := range authFlow.Vulns {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("AUTH-%d", len(res.Findings)),
				"Auth Vulnerability: "+v.Type,
				v.Severity, target, v.Description, v.URL, v.Evidence,
			))
		}
	}

	bizEng := bizlogic.New(bizlogic.TestConfig{
		Target:  target,
		BaseURL: target,
		Timeout: 30 * time.Second,
	})
	bizFindings := bizEng.Run(ctx)
	for _, f := range bizFindings {
		res.Findings = append(res.Findings, toAgentFinding(
			fmt.Sprintf("BIZLOGIC-%d", len(res.Findings)),
			"Business Logic: "+f.Type,
			strings.ToUpper(f.Severity), f.Endpoint, f.Description, f.PoC, "",
		))
	}

	broEng := broffensive.New()
	session, err := broEng.CaptureSession(ctx, target)
	if err != nil {
		logger.Error(fmt.Sprintf("[Worker] Browser session capture failed: %v", err))
	} else if session != nil {
		if session.Title != "" {
			res.TechStack = append(res.TechStack, "title:"+session.Title)
		}

		epResults := broEng.EnumerateEndpoints(ctx, target)
		res.DiscoveredEPs = append(res.DiscoveredEPs, epResults...)

		xssResults := broEng.DetectStoredXSS(ctx, target)
		for _, x := range xssResults {
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("STOREDXSS-%d", len(res.Findings)),
				"Stored XSS",
				"HIGH", x.URL, x.Evidence, x.Payload, x.Evidence,
			))
		}

		csrfResults := broEng.AnalyzeCSRF(ctx, target)
		for _, c := range csrfResults {
			if c.BypassPossible {
				res.Findings = append(res.Findings, toAgentFinding(
					fmt.Sprintf("CSRF-%d", len(res.Findings)),
					"CSRF Bypass",
					"MEDIUM", c.TargetURL, "CSRF chain from "+c.SourceURL, "", "",
				))
			}
		}
	}
}

func runWebshellDetection(ctx context.Context, target string, res *SpecializedScannerResults) {
	if isRemoteTarget(target) {
		return
	}
	cfg := webshell.DefaultConfig()
	d := webshell.NewDetector(cfg)

	webDirs := cfg.WebRoots
	for _, webRoot := range webDirs {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(webRoot); os.IsNotExist(err) {
			continue
		}
		result, err := d.ScanWebRoot(ctx, webRoot)
		if err != nil {
			logger.Warn(fmt.Sprintf("[Worker] Webshell scan failed for %s: %v", webRoot, err))
			continue
		}
		for _, f := range result.Findings {
			evidence := fmt.Sprintf("method=%s confidence=%.2f sigs=%v entropy=%.2f",
				f.DetectionMethod, f.Confidence, f.MatchedSignatures, f.EntropyScore)
			if f.MatchedHash != "" {
				evidence += " hash=" + f.MatchedHash
			}
			res.Findings = append(res.Findings, toAgentFinding(
				fmt.Sprintf("WEBSHELL-%d", len(res.Findings)),
				"Webshell Detected: "+f.FileName,
				string(f.Severity), target,
				fmt.Sprintf("%s - %s on %s", f.DetectionMethod, f.Language, f.FilePath),
				"", evidence,
			))
		}
		if len(result.Findings) > 0 {
			logger.Warn(fmt.Sprintf("[Worker] Webshell scan of %s: %d findings in %d files (%s)",
				webRoot, len(result.Findings), result.Scanned, result.Duration))
		}
	}
}
