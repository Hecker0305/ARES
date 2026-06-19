package cloudscanner

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

var terraformRulesExtended = []Rule{
	{
		Pattern:     regexp.MustCompile(`kms_key_id\s*=\s*""`),
		Resource:    "aws_kms_key",
		Severity:    SevMedium,
		Description: "KMS key ID is empty, using default AWS managed key",
		Remediation: "Specify a KMS key ID for encryption",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)server_side_encryption_configuration`),
		Resource:    "aws_s3_bucket",
		Severity:    SevLow,
		Description: "S3 bucket server-side encryption configuration found",
		Remediation: "Ensure encryption uses AES-256 or aws:kms",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)backup_retention_period\s*=\s*0`),
		Resource:    "aws_db_instance",
		Severity:    SevMedium,
		Description: "RDS backup retention period is 0 (no backups)",
		Remediation: "Set backup_retention_period to at least 7 days",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)delete_on_termination\s*=\s*true`),
		Resource:    "aws_launch_template",
		Severity:    SevMedium,
		Description: "EBS volume set to delete on termination",
		Remediation: "Consider setting delete_on_termination = false for data persistence",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)associate_public_ip_address\s*=\s*true`),
		Resource:    "aws_instance",
		Severity:    SevMedium,
		Description: "EC2 instance has public IP address",
		Remediation: "Use private IPs with NAT gateway for outbound access",
	},
}

func ScanTerraformFileExtended(path string) ([]CloudFinding, error) {
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
		for _, rule := range terraformRules {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   FrameworkTerraform,
				})
			}
		}
		for _, rule := range terraformRulesExtended {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   FrameworkTerraform,
				})
			}
		}
	}
	return findings, scanner.Err()
}
