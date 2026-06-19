package cloud

import (
	"fmt"
	"os/exec"
	"strings"
)

func runAWS(args ...string) (string, error) {
	cmd := exec.Command("aws", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("aws command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func runCurl(args ...string) (string, error) {
	cmd := exec.Command("curl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("curl command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) AWSEnumUsers() (string, error) {
	return runAWS("iam", "list-users")
}

func (e *CloudEngine) AWSEnumRoles() (string, error) {
	return runAWS("iam", "list-roles")
}

func (e *CloudEngine) AWSEnumS3Buckets() (string, error) {
	return runAWS("s3", "ls")
}

func (e *CloudEngine) AWSS3ListFiles(bucket string) (string, error) {
	return runAWS("s3", "ls", fmt.Sprintf("s3://%s", bucket))
}

func (e *CloudEngine) AWSS3Download(bucket, key, output string) (string, error) {
	return runAWS("s3", "cp", fmt.Sprintf("s3://%s/%s", bucket, key), output)
}

func (e *CloudEngine) AWSS3Upload(bucket, file string) (string, error) {
	return runAWS("s3", "cp", file, fmt.Sprintf("s3://%s", bucket))
}

func (e *CloudEngine) AWSS3MakePublic(bucket string) (string, error) {
	return runAWS("s3api", "put-bucket-acl", "--bucket", bucket, "--acl", "public-read")
}

func (e *CloudEngine) AWSEC2DescribeInstances() (string, error) {
	return runAWS("ec2", "describe-instances")
}

func (e *CloudEngine) AWSEC2DescribeSecurityGroups() (string, error) {
	return runAWS("ec2", "describe-security-groups")
}

func (e *CloudEngine) AWSIAMCreateAdminUser(username string) (string, error) {
	out, err := runAWS("iam", "create-user", "--user-name", username)
	if err != nil {
		return "", err
	}
	return out, nil
}

func (e *CloudEngine) AWSIAMCreateAccessKey(username string) (string, error) {
	return runAWS("iam", "create-access-key", "--user-name", username)
}

func (e *CloudEngine) AWSIAMAttachAdminPolicy(username string) (string, error) {
	return runAWS("iam", "attach-user-policy", "--user-name", username, "--policy-arn", "arn:aws:iam::aws:policy/AdministratorAccess")
}

func (e *CloudEngine) AWSLambdaListFunctions() (string, error) {
	return runAWS("lambda", "list-functions")
}

func (e *CloudEngine) AWSCloudFormationListStacks() (string, error) {
	return runAWS("cloudformation", "describe-stacks")
}

func (e *CloudEngine) AWSAssumeRole(roleArn, sessionName string) (string, error) {
	return runAWS("sts", "assume-role", "--role-arn", roleArn, "--role-session-name", sessionName)
}

func (e *CloudEngine) AWSGetCallerIdentity() (string, error) {
	return runAWS("sts", "get-caller-identity")
}

func (e *CloudEngine) AWSGenerateCredReport() (string, error) {
	return runAWS("iam", "generate-credential-report")
}

func (e *CloudEngine) AWSPacuRun(module string) (string, error) {
	cmd := exec.Command("pacu", "--module", module)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pacu command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) AWSMetadataQuery(path string) (string, error) {
	return runCurl("-s", fmt.Sprintf("http://169.254.169.254/latest/meta-data/%s", path))
}

func (e *CloudEngine) AWSMetadataToken() (string, error) {
	cmd := exec.Command("curl", "-s", "-X", "PUT", "http://169.254.169.254/latest/api/token", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get IMDSv2 token: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) AWSEC2StartSSM(instanceID, region string) (string, error) {
	cmd := exec.Command("aws", "ssm", "start-session", "--target", instanceID, "--region", region)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("SSM session failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}
