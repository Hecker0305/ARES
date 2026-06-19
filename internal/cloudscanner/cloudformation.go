package cloudscanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ares/engine/internal/kubescan"
)

var cloudFormationRulesExtended = []Rule{
	{
		Pattern:     regexp.MustCompile(`(?i)"Action":\s*"\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevCritical,
		Description: "IAM policy with wildcard action (*)",
		Remediation: "Replace * with specific required actions following least privilege principle",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)"Principal":\s*"\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevCritical,
		Description: "IAM policy allows any principal",
		Remediation: "Restrict Principal to specific AWS accounts or IAM roles",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)PublicAccessBlockConfiguration`),
		Resource:    "AWS::S3::Bucket",
		Severity:    SevMedium,
		Description: "S3 bucket public access block configuration found",
		Remediation: "Ensure BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets are all set to true",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)VersioningConfiguration`),
		Resource:    "AWS::S3::Bucket",
		Severity:    SevLow,
		Description: "S3 bucket versioning configuration found",
		Remediation: "Ensure versioning is enabled for data protection",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)StorageEncrypted:\s*false`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevHigh,
		Description: "RDS storage encryption is disabled",
		Remediation: "Set StorageEncrypted: true",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)MultiAZ:\s*false`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevMedium,
		Description: "RDS instance is not Multi-AZ (no high availability)",
		Remediation: "Set MultiAZ: true for production databases",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)AutoMinorVersionUpgrade:\s*false`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevLow,
		Description: "RDS auto minor version upgrade is disabled",
		Remediation: "Set AutoMinorVersionUpgrade: true for security patches",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)IamInstanceProfile`),
		Resource:    "AWS::EC2::Instance",
		Severity:    SevLow,
		Description: "EC2 instance uses IAM instance profile",
		Remediation: "Ensure instance profile follows least privilege principle",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)UserData:`),
		Resource:    "AWS::EC2::Instance",
		Severity:    SevMedium,
		Description: "EC2 instance has UserData (may contain secrets)",
		Remediation: "Avoid hardcoding secrets in UserData, use Secrets Manager or SSM Parameter Store",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)Fn::GetAtt.*SecretAccessKey`),
		Resource:    "AWS::IAM::AccessKey",
		Severity:    SevCritical,
		Description: "IAM access key secret exposed via Fn::GetAtt",
		Remediation: "Use Secrets Manager to store and retrieve access key secrets",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)AccessKeyId`),
		Resource:    "AWS::IAM::AccessKey",
		Severity:    SevHigh,
		Description: "IAM access key created in CloudFormation",
		Remediation: "Use IAM roles instead of access keys where possible",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)BucketPolicy`),
		Resource:    "AWS::S3::BucketPolicy",
		Severity:    SevMedium,
		Description: "S3 bucket policy found",
		Remediation: "Review bucket policy to ensure it does not allow public access",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)"s3:\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevHigh,
		Description: "IAM policy allows all S3 actions",
		Remediation: "Restrict S3 actions to specific required operations",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)"ec2:\*"`),
		Resource:    "AWS::IAM::Policy",
		Severity:    SevHigh,
		Description: "IAM policy allows all EC2 actions",
		Remediation: "Restrict EC2 actions to specific required operations",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SecurityGroupIngress.*FromPort:\s*22`),
		Resource:    "AWS::EC2::SecurityGroup",
		Severity:    SevHigh,
		Description: "Security group allows SSH (port 22) access",
		Remediation: "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)SecurityGroupIngress.*FromPort:\s*3389`),
		Resource:    "AWS::EC2::SecurityGroup",
		Severity:    SevHigh,
		Description: "Security group allows RDP (port 3389) access",
		Remediation: "Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager",
	},
	{
		Pattern:     regexp.MustCompile(`DeletionPolicy:\s*Delete`),
		Resource:    "AWS::RDS::DBInstance",
		Severity:    SevMedium,
		Description: "RDS instance has DeletionPolicy set to Delete (risk of data loss)",
		Remediation: "Consider using DeletionPolicy: Retain or Snapshot for production databases",
	},
	{
		Pattern:     regexp.MustCompile(`EnableTerminationProtection:\s*false`),
		Resource:    "AWS::EC2::Instance",
		Severity:    SevMedium,
		Description: "EC2 instance termination protection is disabled",
		Remediation: "Set EnableTerminationProtection: true to prevent accidental termination",
	},
}

func ScanCloudFormationFileExtended(path string) ([]CloudFinding, error) {
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
		for _, rule := range cloudFormationRules {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   FrameworkCloudFormation,
				})
			}
		}
		for _, rule := range cloudFormationRulesExtended {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, CloudFinding{
					File:        path,
					Line:        lineNum,
					Resource:    rule.Resource,
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Framework:   FrameworkCloudFormation,
				})
			}
		}
	}
	return findings, scanner.Err()
}

func ScanDirectoryWithK8s(root string) ([]CloudFinding, error) {
	var allFindings []CloudFinding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		name := strings.ToLower(info.Name())

		switch {
		case ext == ".tf" || name == "terraform.tfvars":
			findings, err := ScanTerraformFile(path)
			if err != nil {
				return err
			}
			allFindings = append(allFindings, findings...)

		case ext == ".yaml" || ext == ".yml" || ext == ".json":
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(data)
			if isCloudFormationTemplate(content) {
				findings, err := ScanCloudFormationFileExtended(path)
				if err != nil {
					return err
				}
				allFindings = append(allFindings, findings...)
			} else if isKubernetesManifest(content) {
				k8sFindings, err := kubescan.ScanKubernetesFile(path)
				if err != nil {
					return err
				}
				for _, kf := range k8sFindings {
					allFindings = append(allFindings, CloudFinding{
						File:        kf.File,
						Line:        kf.Line,
						Resource:    kf.Resource,
						Severity:    Severity(kf.Severity),
						Description: kf.Description,
						Remediation: kf.Remediation,
						Framework:   CloudFramework(kf.Framework),
					})
				}
			}
		}
		return nil
	})
	return allFindings, err
}

func isKubernetesManifest(content string) bool {
	content = strings.TrimSpace(content)
	indicators := []string{
		"apiVersion:", "kind:", "metadata:", "spec:",
		"apiVersion: v1", "apiVersion: apps/v1", "apiVersion: networking.k8s.io",
		"kind: Pod", "kind: Deployment", "kind: Service", "kind: Ingress",
		"kind: ConfigMap", "kind: Secret", "kind: ServiceAccount",
		"kind: ClusterRole", "kind: ClusterRoleBinding", "kind: Role",
	}
	matchCount := 0
	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			matchCount++
		}
	}
	return matchCount >= 2
}
