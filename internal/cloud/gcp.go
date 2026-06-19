package cloud

import (
	"fmt"
	"os/exec"
	"strings"
)

func runGcloud(args ...string) (string, error) {
	cmd := exec.Command("gcloud", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gcloud command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func runGsutil(args ...string) (string, error) {
	cmd := exec.Command("gsutil", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gsutil command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) GCPLoginWithKey(keyFile string) (string, error) {
	return runGcloud("auth", "activate-service-account", "--key-file", keyFile)
}

func (e *CloudEngine) GCPListInstances(project string) (string, error) {
	return runGcloud("compute", "instances", "list", "--project", project)
}

func (e *CloudEngine) GCPListBuckets(project string) (string, error) {
	return runGsutil("ls", "-p", project)
}

func (e *CloudEngine) GCPBucketListFiles(bucket string) (string, error) {
	return runGsutil("ls", fmt.Sprintf("gs://%s", bucket))
}

func (e *CloudEngine) GCPBucketDownload(bucket, object, output string) (string, error) {
	return runGsutil("cp", fmt.Sprintf("gs://%s/%s", bucket, object), output)
}

func (e *CloudEngine) GCPBucketUpload(bucket, file string) (string, error) {
	return runGsutil("cp", file, fmt.Sprintf("gs://%s", bucket))
}

func (e *CloudEngine) GCPBucketMakePublic(bucket string) (string, error) {
	return runGsutil("iam", "ch", "allUsers:objectViewer", fmt.Sprintf("gs://%s", bucket))
}

func (e *CloudEngine) GCPListIAMPolicy(project string) (string, error) {
	return runGcloud("projects", "get-iam-policy", project)
}

func (e *CloudEngine) GCPAddIAMBinding(project, member, role string) (string, error) {
	return runGcloud("projects", "add-iam-policy-binding", project, "--member", member, "--role", role)
}

func (e *CloudEngine) GCPListFunctions(project, region string) (string, error) {
	return runGcloud("functions", "list", "--project", project, "--region", region)
}

func (e *CloudEngine) GCPListKMSKeys(project, location, keyring string) (string, error) {
	return runGcloud("kms", "keys", "list", "--project", project, "--location", location, "--keyring", keyring)
}

func (e *CloudEngine) GCPListSQLInstances(project string) (string, error) {
	return runGcloud("sql", "instances", "list", "--project", project)
}

func (e *CloudEngine) GCPListServiceAccounts(project string) (string, error) {
	return runGcloud("iam", "service-accounts", "list", "--project", project)
}

func (e *CloudEngine) GCPCreateServiceAccountKey(saEmail, keyFile string) (string, error) {
	return runGcloud("iam", "service-accounts", "keys", "create", keyFile, "--iam-account", saEmail)
}

func (e *CloudEngine) GCPMetadataQuery(path string) (string, error) {
	cmd := exec.Command("curl", "-s", "-H", "Metadata-Flavor: Google", fmt.Sprintf("http://169.254.169.254/computeMetadata/v1/%s", path))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GCP metadata query failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *CloudEngine) GCPScouteSuite(project string) (string, error) {
	cmd := exec.Command("scout", "--provider", "gcp", "--project-id", project)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ScoutSuite command failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}
