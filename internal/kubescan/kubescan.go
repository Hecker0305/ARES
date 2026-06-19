package kubescan

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type CloudFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Framework   string `json:"framework"`
}

const FrameworkKubernetes = "kubernetes"

const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

type K8sRule struct {
	Pattern     *regexp.Regexp
	Resource    string
	Severity    string
	Description string
	Remediation string
}

var kubernetesRules = []K8sRule{
	{
		Pattern:     regexp.MustCompile(`(?i)privileged:\s*true`),
		Resource:    "Pod/Container",
		Severity:    SevCritical,
		Description: "Container running in privileged mode",
		Remediation: "Set privileged: false and use specific capabilities instead",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)allowPrivilegeEscalation:\s*true`),
		Resource:    "Pod/Container",
		Severity:    SevHigh,
		Description: "Container allows privilege escalation",
		Remediation: "Set allowPrivilegeEscalation: false",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)runAsUser:\s*0`),
		Resource:    "Pod/Container",
		Severity:    SevHigh,
		Description: "Container running as root (UID 0)",
		Remediation: "Set runAsUser to non-zero UID and runAsNonRoot: true",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostNetwork:\s*true`),
		Resource:    "Pod",
		Severity:    SevHigh,
		Description: "Pod uses host network namespace",
		Remediation: "Set hostNetwork: false unless absolutely required",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostPID:\s*true`),
		Resource:    "Pod",
		Severity:    SevHigh,
		Description: "Pod uses host PID namespace",
		Remediation: "Set hostPID: false unless absolutely required",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostIPC:\s*true`),
		Resource:    "Pod",
		Severity:    SevMedium,
		Description: "Pod uses host IPC namespace",
		Remediation: "Set hostIPC: false unless absolutely required",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostPath:`),
		Resource:    "Pod/Volume",
		Severity:    SevHigh,
		Description: "Pod uses hostPath volume",
		Remediation: "Use persistent volumes instead of hostPath",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)imagePullPolicy:\s*Never`),
		Resource:    "Pod/Container",
		Severity:    SevMedium,
		Description: "Container image pull policy set to Never",
		Remediation: "Use Always or IfNotPresent to ensure latest image",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)capabilities:\s*add:`),
		Resource:    "Pod/Container",
		Severity:    SevMedium,
		Description: "Container adds Linux capabilities",
		Remediation: "Remove unnecessary capabilities, use minimal set",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SYS_ADMIN`),
		Resource:    "Pod/Container",
		Severity:    SevCritical,
		Description: "Container has SYS_ADMIN capability (near-root privileges)",
		Remediation: "Remove SYS_ADMIN capability, use specific capabilities instead",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)NET_ADMIN`),
		Resource:    "Pod/Container",
		Severity:    SevMedium,
		Description: "Container has NET_ADMIN capability",
		Remediation: "Remove NET_ADMIN unless required for network configuration",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)serviceAccountToken`),
		Resource:    "Pod",
		Severity:    SevMedium,
		Description: "Pod mounts service account token",
		Remediation: "Set automountServiceAccountToken: false if not needed",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)cluster-admin`),
		Resource:    "ClusterRoleBinding",
		Severity:    SevCritical,
		Description: "Cluster-admin role bound to service account",
		Remediation: "Use least-privilege roles instead of cluster-admin; create dedicated Role with minimal permissions",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)resources:\s*(?:$|\{\}|\[\])`),
		Resource:    "Pod/Container",
		Severity:    SevLow,
		Description: "No resource limits defined for container",
		Remediation: "Define resource requests and limits",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)replicas:\s*[0-1]\s*$`),
		Resource:    "Deployment",
		Severity:    SevLow,
		Description: "Deployment has 0 or 1 replicas (no HA)",
		Remediation: "Set replicas to at least 2 for high availability",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)secretKeyRef`),
		Resource:    "Pod/Container",
		Severity:    SevLow,
		Description: "Secret mounted as environment variable",
		Remediation: "Use volume mounts for secrets instead of env vars",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)readOnlyRootFilesystem:\s*false`),
		Resource:    "Pod/Container",
		Severity:    SevMedium,
		Description: "Container root filesystem is writable",
		Remediation: "Set readOnlyRootFilesystem: true",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)nodeSelector`),
		Resource:    "Pod",
		Severity:    SevLow,
		Description: "Pod uses node selector",
		Remediation: "Ensure node selector does not expose sensitive nodes",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)seccompProfile`),
		Resource:    "Pod/SecurityContext",
		Severity:    SevMedium,
		Description: "Seccomp profile not configured or set to Unconfined",
		Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)appArmorProfile`),
		Resource:    "Pod/Annotation",
		Severity:    SevMedium,
		Description: "AppArmor profile not configured",
		Remediation: "Set container.apparmor.security.beta.kubernetes.io annotation with runtime/default profile",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostPort:\s*\d+`),
		Resource:    "Pod/Container",
		Severity:    SevHigh,
		Description: "Container exposes host port",
		Remediation: "Avoid hostPort unless absolutely necessary; use NodePort or Ingress instead",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)automountServiceAccountToken:\s*true`),
		Resource:    "ServiceAccount",
		Severity:    SevHigh,
		Description: "Service account token is automatically mounted",
		Remediation: "Set automountServiceAccountToken: false if pod does not need API access",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)NET_RAW`),
		Resource:    "Pod/Container",
		Severity:    SevMedium,
		Description: "NET_RAW capability allows raw socket creation (ICMP spoofing, ARP poison)",
		Remediation: "Add NET_RAW to capabilities.drop in securityContext",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)fsGroup:\s*0`),
		Resource:    "Pod/SecurityContext",
		Severity:    SevMedium,
		Description: "Pod fsGroup is set to root (0)",
		Remediation: "Set fsGroup to a non-zero GID specific to the application",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)sysctls:\s*-`),
		Resource:    "Pod/SecurityContext",
		Severity:    SevHigh,
		Description: "Unsafe sysctl parameters may be configured",
		Remediation: "Remove dangerous sysctls (kernel.*, net.ipv4.*, vm.*) unless validated",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)priorityClassName|PriorityClass`),
		Resource:    "Pod/PriorityClass",
		Severity:    SevLow,
		Description: "Pod uses priority class that may allow resource starvation",
		Remediation: "Ensure priority class ordering is designed correctly",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)(?:spec\.)?volumeClaimTemplates`),
		Resource:    "StatefulSet",
		Severity:    SevLow,
		Description: "StatefulSet uses volumeClaimTemplates without retention policy",
		Remediation: "Set persistentVolumeClaimRetentionPolicy for StatefulSet",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)shareProcessNamespace:\s*true`),
		Resource:    "Pod/Spec",
		Severity:    SevMedium,
		Description: "Pod shares process namespace between containers",
		Remediation: "Set shareProcessNamespace: false unless containers need to signal each other",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)hostAliases:`),
		Resource:    "Pod/Spec",
		Severity:    SevLow,
		Description: "Pod uses hostAliases for DNS override (possible cache poisoning abuse)",
		Remediation: "Use DNS records instead of hostAliases; audit all entries",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)securityContext:\s*\n`),
		Resource:    "Pod",
		Severity:    SevLow,
		Description: "Empty securityContext block — does not enforce any restrictions",
		Remediation: "Add securityContext settings (runAsNonRoot, readOnlyRootFilesystem, capabilities)",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)sidecar\.istio\.io/inject:\s*"true"`),
		Resource:    "Pod/Annotation",
		Severity:    SevLow,
		Description: "Istio sidecar injection enabled (increases attack surface if not needed)",
		Remediation: "Disable sidecar injection unless service mesh is required for the workload",
	},
}

func ScanKubernetesFile(path string) ([]CloudFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close()

	var findings []CloudFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, rule := range kubernetesRules {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   FrameworkKubernetes,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, err
	}

	findingSet := deduplicateFindings(findings)
	return findingSet, nil
}

func ScanKubernetesYAML(path string) ([]CloudFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	var findings []CloudFinding

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	findings = append(findings, analyzeYAMLNode(&doc, path)...)

	return findings, nil
}

func analyzeYAMLNode(node *yaml.Node, path string) []CloudFinding {
	var findings []CloudFinding

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				continue
			}
			key := node.Content[i].Value
			value := node.Content[i+1]

			switch key {
			case "privileged":
				if value.Value == "true" {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "Pod/Container",
						Severity:    SevCritical,
						Description: "Container running in privileged mode",
						Remediation: "Set privileged: false",
						Framework:   FrameworkKubernetes,
					})
				}
			case "allowPrivilegeEscalation":
				if value.Value == "true" {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "Pod/Container",
						Severity:    SevHigh,
						Description: "Container allows privilege escalation",
						Remediation: "Set allowPrivilegeEscalation: false",
						Framework:   FrameworkKubernetes,
					})
				}
			case "runAsUser":
				if value.Value == "0" {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "Pod/Container",
						Severity:    SevHigh,
						Description: "Container running as root (UID 0)",
						Remediation: "Set runAsUser to non-zero UID",
						Framework:   FrameworkKubernetes,
					})
				}
			case "hostNetwork":
				if value.Value == "true" {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "Pod",
						Severity:    SevHigh,
						Description: "Pod uses host network namespace",
						Remediation: "Set hostNetwork: false",
						Framework:   FrameworkKubernetes,
					})
				}
			case "hostPID":
				if value.Value == "true" {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "Pod",
						Severity:    SevHigh,
						Description: "Pod uses host PID namespace",
						Remediation: "Set hostPID: false",
						Framework:   FrameworkKubernetes,
					})
				}
			case "roleRef":
				if isClusterAdminBinding(node, i) {
					findings = append(findings, CloudFinding{
						File:        path,
						Line:        value.Line,
						Resource:    "ClusterRoleBinding",
						Severity:    SevCritical,
						Description: "Cluster-admin role bound to service account - violates least-privilege principle",
						Remediation: "Replace cluster-admin with a dedicated Role granting only required permissions",
						Framework:   FrameworkKubernetes,
					})
				}
			}
		}
	}

	for _, child := range node.Content {
		findings = append(findings, analyzeYAMLNode(child, path)...)
	}

	return findings
}

func isClusterAdminBinding(node *yaml.Node, roleRefIdx int) bool {
	if roleRefIdx+1 >= len(node.Content) {
		return false
	}
	roleRefNode := node.Content[roleRefIdx+1]
	if roleRefNode.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(roleRefNode.Content); i += 2 {
		if i+1 >= len(roleRefNode.Content) {
			continue
		}
		if roleRefNode.Content[i].Value == "name" && roleRefNode.Content[i+1].Value == "cluster-admin" {
			return true
		}
	}
	return false
}

func ScanDirectory(dir string) ([]CloudFinding, error) {
	var allFindings []CloudFinding

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			path := dir + "/" + name

			yamlFindings, err := ScanKubernetesYAML(path)
			if err == nil {
				allFindings = append(allFindings, yamlFindings...)
			}

			lineFindings, err := ScanKubernetesFile(path)
			if err == nil {
				allFindings = append(allFindings, lineFindings...)
			}
		}
	}

	return allFindings, nil
}

func deduplicateFindings(findings []CloudFinding) []CloudFinding {
	seen := make(map[string]bool)
	var unique []CloudFinding

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s:%s", f.File, f.Line, f.Resource, f.Description)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}
