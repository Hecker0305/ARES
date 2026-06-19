package cloudscanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ares/engine/internal/secrets"
)

type CloudFramework string

const (
	FrameworkTerraform      CloudFramework = "terraform"
	FrameworkCloudFormation CloudFramework = "cloudformation"
)

type Severity string

const (
	SevCritical Severity = "Critical"
	SevHigh     Severity = "High"
	SevMedium   Severity = "Medium"
	SevLow      Severity = "Low"
)

type CloudFinding struct {
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Resource    string         `json:"resource"`
	Severity    Severity       `json:"severity"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	Framework   CloudFramework `json:"framework"`
}

type Rule struct {
	Pattern     *regexp.Regexp
	Resource    string
	Severity    Severity
	Description string
	Remediation string
}

type CredentialSource string

const (
	CredSourceIAMRole    CredentialSource = "iam_role"
	CredSourceEnvVar     CredentialSource = "environment"
	CredSourceConfigFile CredentialSource = "config_file"
	CredSourceMetadata   CredentialSource = "instance_metadata"
	CredSourceHardcoded  CredentialSource = "hardcoded"
)

type CredentialValidator struct {
	source          CredentialSource
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	validated       bool
}

func NewCredentialValidator() *CredentialValidator {
	return &CredentialValidator{}
}

func (cv *CredentialValidator) Validate() error {
	if cv.validated {
		return nil
	}

	accessKey := secrets.Get("AWS_ACCESS_KEY_ID")
	secretKey := secrets.Get("AWS_SECRET_ACCESS_KEY")
	sessionToken := secrets.Get("AWS_SESSION_TOKEN")
	region := os.Getenv("AWS_DEFAULT_REGION")

	if accessKey != "" && secretKey != "" {
		cv.accessKeyID = accessKey
		cv.secretAccessKey = secretKey
		cv.sessionToken = sessionToken
		cv.region = region
		cv.source = CredSourceEnvVar
		cv.validated = true
		return nil
	}

	iamRole := secrets.Get("AWS_IAM_ROLE_ARN")
	if iamRole != "" {
		cv.source = CredSourceIAMRole
		cv.validated = true
		return nil
	}

	metadataURI := os.Getenv("AWS_EC2_METADATA_V1_DISABLED")
	if metadataURI == "" {
		cv.source = CredSourceMetadata
		cv.validated = true
		return nil
	}

	configPath := os.Getenv("AWS_CONFIG_FILE")
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			configPath = filepath.Join(homeDir, ".aws", "config")
		}
	}
	if _, err := os.Stat(configPath); err == nil {
		cv.source = CredSourceConfigFile
		cv.validated = true
		return nil
	}

	return fmt.Errorf("no valid cloud credentials found; use environment variables, IAM roles, or AWS config file")
}

func (cv *CredentialValidator) Source() CredentialSource {
	return cv.source
}

func (cv *CredentialValidator) IsHardcoded() bool {
	return cv.source == CredSourceHardcoded
}

func (cv *CredentialValidator) Region() string {
	return cv.region
}

func DetectHardcodedCredentials(content string) []CloudFinding {
	var findings []CloudFinding

	hardcodedPatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    Severity
	}{
		{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["']?[A-Z0-9]{16,}["']?`), "Hardcoded AWS credentials detected", SevCritical},
		{regexp.MustCompile(`(?i)(password|passwd|secret)\s*[:=]\s*["'][^"']{8,}["']`), "Hardcoded password or secret detected", SevCritical},
		{regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`), "Hardcoded API key detected", SevHigh},
		{regexp.MustCompile(`(?i)private[_-]?key\s*[:=]\s*["']-----BEGIN`), "Hardcoded private key detected", SevCritical},
		{regexp.MustCompile(`(?i)(AKIA|ASIA)[A-Z0-9]{16}`), "AWS Access Key ID in plaintext", SevCritical},
	}

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		for _, pat := range hardcodedPatterns {
			if pat.regex.MatchString(line) {
				findings = append(findings, CloudFinding{
					Line:        lineNum + 1,
					Resource:    "hardcoded_credential",
					Severity:    pat.severity,
					Description: pat.description,
					Remediation: "Remove hardcoded credentials; use IAM roles, environment variables, or a secrets manager",
					Framework:   FrameworkTerraform,
				})
			}
		}
	}

	return findings
}

var terraformRules = []Rule{
	{
		Pattern:     regexp.MustCompile(`acl\s*=\s*"public-read"`),
		Resource:    "aws_s3_bucket",
		Severity:    SevCritical,
		Description: "S3 bucket has public read access via ACL",
		Remediation: "Remove `acl = \"public-read\"` or use `acl = \"private\"`",
	},
	{
		Pattern:     regexp.MustCompile(`acl\s*=\s*"public-read-write"`),
		Resource:    "aws_s3_bucket",
		Severity:    SevCritical,
		Description: "S3 bucket has public read-write access via ACL",
		Remediation: "Remove public ACL or use `acl = \"private\"`",
	},
	{
		Pattern:     regexp.MustCompile(`cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"\s*\]?`),
		Resource:    "aws_security_group_rule",
		Severity:    SevCritical,
		Description: "Security group allows inbound traffic from 0.0.0.0/0",
		Remediation: "Restrict ingress CIDR blocks to specific IPs or VPC ranges",
	},
	{
		Pattern:     regexp.MustCompile(`encrypted\s*=\s*false`),
		Resource:    "aws_ebs_volume",
		Severity:    SevHigh,
		Description: "EBS volume encryption is disabled",
		Remediation: "Set `encrypted = true` and specify a KMS key",
	},
	{
		Pattern:     regexp.MustCompile(`effect\s*=\s*"Allow".*Action\s*=\s*"\*"`),
		Resource:    "aws_iam_policy",
		Severity:    SevCritical,
		Description: "IAM policy uses wildcard (*) action, granting excessive permissions",
		Remediation: "Restrict IAM actions to only those required following least-privilege principle",
	},
	{
		Pattern:     regexp.MustCompile(`effect\s*=\s*"Allow"`),
		Resource:    "aws_iam_policy",
		Severity:    SevMedium,
		Description: "IAM policy has Allow effect",
		Remediation: "Ensure IAM policies follow least-privilege and have appropriate conditions",
	},
	{
		Pattern:     regexp.MustCompile(`publicly_accessible\s*=\s*true`),
		Resource:    "aws_db_instance",
		Severity:    SevCritical,
		Description: "RDS instance is publicly accessible",
		Remediation: "Set `publicly_accessible = false` and use private subnets",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)cloudtrail`),
		Resource:    "aws_cloudtrail",
		Severity:    SevHigh,
		Description: "CloudTrail configuration detected - verify trails cover all regions and management events",
		Remediation: "Enable CloudTrail with multi-region trail and management/read-write events",
	},
	{
		Pattern:     regexp.MustCompile(`logging\s*\{`),
		Resource:    "aws_s3_bucket_logging",
		Severity:    SevLow,
		Description: "Server access logging configured for S3 bucket",
		Remediation: "Ensure logging is enabled for all S3 buckets",
	},
	{
		Pattern:     regexp.MustCompile(`versioning.*enabled\s*=\s*false`),
		Resource:    "aws_s3_bucket_versioning",
		Severity:    SevMedium,
		Description: "S3 bucket versioning is disabled",
		Remediation: "Enable versioning to protect against accidental deletion",
	},
}

var cloudFormationRules = []Rule{
	{
		Pattern:     regexp.MustCompile(`CidrIp:\s*0\.0\.0\.0/0`),
		Resource:    "AWS::EC2::SecurityGroupIngress",
		Severity:    SevCritical,
		Description: "Security group ingress allows traffic from 0.0.0.0/0",
		Remediation: "Restrict CidrIp to specific IP ranges",
	},
	{
		Pattern:     regexp.MustCompile(`"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevCritical,
		Description: "IAM policy with wildcard action",
		Remediation: "Restrict IAM actions to specific required operations",
	},
	{
		Pattern:     regexp.MustCompile(`PubliclyAccessible:\s*true`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevCritical,
		Description: "RDS instance is publicly accessible",
		Remediation: "Set PubliclyAccessible to false",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Encrypted:\s*false`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevHigh,
		Description: "RDS instance encryption is disabled",
		Remediation: "Enable encryption by setting Encrypted: true",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SSEAlgorithm:\s*"AES256"`),
		Resource:    "AWS::S3::Bucket",
		Severity:    SevLow,
		Description: "S3 bucket uses SSE-S3 encryption (not KMS)",
		Remediation: "Consider using KMS-managed keys for encryption",
	},
	{
		Pattern:     regexp.MustCompile(`"Action":\s*"iam:\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevCritical,
		Description: "IAM policy allows all iam actions",
		Remediation: "Restrict IAM actions to specific required operations",
	},
	{
		Pattern:     regexp.MustCompile(`"Resource":\s*"\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevHigh,
		Description: "IAM policy grants access to all resources (*)",
		Remediation: "Restrict IAM resource to specific ARNs",
	},
	{
		Pattern:     regexp.MustCompile(`LoggingConfiguration:\s*\{\s*$`),
		Resource:    "AWS::S3::Bucket",
		Severity:    SevLow,
		Description: "S3 bucket logging configuration found",
		Remediation: "Ensure logging configuration is complete",
	},
}

func scanFile(path string, rules []Rule, framework CloudFramework) ([]CloudFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close()

	var findings []CloudFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   framework,
				})
			}
		}
	}
	return findings, scanner.Err()
}

func ScanTerraformFile(path string) ([]CloudFinding, error) {
	return scanFile(path, terraformRules, FrameworkTerraform)
}

func ScanCloudFormationFile(path string) ([]CloudFinding, error) {
	return scanFile(path, cloudFormationRules, FrameworkCloudFormation)
}

func ScanDirectory(root string) ([]CloudFinding, error) {
	var allFindings []CloudFinding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		name := strings.ToLower(d.Name())

		switch {
		case ext == ".tf" || name == "terraform.tfvars":
			findings, err := ScanTerraformFile(path)
			if err != nil {
				return err
			}
			allFindings = append(allFindings, findings...)

			data, err := os.ReadFile(path)
			if err == nil {
				credFindings := DetectHardcodedCredentials(string(data))
				for i := range credFindings {
					credFindings[i].File = path
				}
				allFindings = append(allFindings, credFindings...)
			}

		case ext == ".yaml" || ext == ".yml" || ext == ".json":
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(data)
			if isCloudFormationTemplate(content) {
				findings, err := ScanCloudFormationFile(path)
				if err != nil {
					return err
				}
				allFindings = append(allFindings, findings...)
			}
			credFindings := DetectHardcodedCredentials(content)
			for i := range credFindings {
				credFindings[i].File = path
			}
			allFindings = append(allFindings, credFindings...)
		}
		return nil
	})
	return allFindings, err
}

func isCloudFormationTemplate(content string) bool {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "AWSTemplateFormatVersion") ||
		strings.HasPrefix(content, "---\nAWSTemplateFormatVersion") ||
		strings.HasPrefix(content, "{\"AWSTemplateFormatVersion") ||
		strings.Contains(content, "AWS::") {
		return true
	}
	return strings.Contains(content, "Type: \"AWS::") ||
		strings.Contains(content, "\"Type\": \"AWS::") ||
		strings.Contains(content, "Type: AWS::")
}

func ValidateConfigLine(line string) ([]CloudFinding, error) {
	var findings []CloudFinding
	for _, rule := range terraformRules {
		if rule.Pattern.MatchString(line) {
			findings = append(findings, CloudFinding{
				Line:        1,
				Resource:    rule.Resource,
				Severity:    rule.Severity,
				Description: rule.Description,
				Remediation: rule.Remediation,
				Framework:   FrameworkTerraform,
			})
		}
	}
	for _, rule := range cloudFormationRules {
		if rule.Pattern.MatchString(line) {
			findings = append(findings, CloudFinding{
				Line:        1,
				Resource:    rule.Resource,
				Severity:    rule.Severity,
				Description: rule.Description,
				Remediation: rule.Remediation,
				Framework:   FrameworkCloudFormation,
			})
		}
	}
	credFindings := DetectHardcodedCredentials(line)
	findings = append(findings, credFindings...)
	return findings, nil
}

func DedupFindings(findings []CloudFinding) []CloudFinding {
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
