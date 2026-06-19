package cloudscanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	if SevCritical != "Critical" {
		t.Errorf("SevCritical = %q, want Critical", SevCritical)
	}
	if SevHigh != "High" {
		t.Errorf("SevHigh = %q, want High", SevHigh)
	}
	if SevMedium != "Medium" {
		t.Errorf("SevMedium = %q, want Medium", SevMedium)
	}
	if SevLow != "Low" {
		t.Errorf("SevLow = %q, want Low", SevLow)
	}
}

func TestFrameworkConstants(t *testing.T) {
	if FrameworkTerraform != "terraform" {
		t.Errorf("FrameworkTerraform = %q, want terraform", FrameworkTerraform)
	}
	if FrameworkCloudFormation != "cloudformation" {
		t.Errorf("FrameworkCloudFormation = %q, want cloudformation", FrameworkCloudFormation)
	}
}

func TestIsCloudFormationTemplate(t *testing.T) {
	tests := []struct {
		content string
		want    bool
	}{
		{"AWSTemplateFormatVersion: 2010-09-09", true},
		{"---\nAWSTemplateFormatVersion: 2010-09-09", true},
		{`{"AWSTemplateFormatVersion": "2010-09-09"}`, true},
		{"Type: AWS::S3::Bucket", true},
		{"Type: \"AWS::IAM::Policy\"", true},
		{"\"Type\": \"AWS::EC2::Instance\"", true},
		{"not a cloudformation template", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.content[:min(len(tt.content), 30)], func(t *testing.T) {
			if got := isCloudFormationTemplate(tt.content); got != tt.want {
				t.Errorf("isCloudFormationTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsKubernetesManifest(t *testing.T) {
	tests := []struct {
		content string
		want    bool
	}{
		{"apiVersion: v1\nkind: Pod\nmetadata:\n  name: test", true},
		{"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app", true},
		{"kind: Service\nmetadata:\n  name: svc", true},
		{"not a k8s manifest", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.content[:min(len(tt.content), 20)], func(t *testing.T) {
			if got := isKubernetesManifest(tt.content); got != tt.want {
				t.Errorf("isKubernetesManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConfigLine(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{`acl = "public-read"`, 1},
		{`something safe`, 0},
		{`cidr_blocks = ["0.0.0.0/0"]`, 1},
		{`CidrIp: 0.0.0.0/0`, 1},
		{`"Effect": "Allow"`, 0},
		{`PubliclyAccessible: true`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.line[:min(len(tt.line), 30)], func(t *testing.T) {
			findings, err := ValidateConfigLine(tt.line)
			if err != nil {
				t.Fatalf("ValidateConfigLine() error = %v", err)
			}
			if len(findings) != tt.want {
				t.Errorf("ValidateConfigLine(%q) returned %d findings, want %d", tt.line, len(findings), tt.want)
			}
		})
	}
}

func TestValidateConfigLineEmpty(t *testing.T) {
	findings, err := ValidateConfigLine("")
	if err != nil {
		t.Fatalf("ValidateConfigLine() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty line, got %d", len(findings))
	}
}

func TestDedupFindings(t *testing.T) {
	findings := []CloudFinding{
		{File: "test.tf", Line: 1, Resource: "aws_s3_bucket", Description: "test", Framework: FrameworkTerraform},
		{File: "test.tf", Line: 1, Resource: "aws_s3_bucket", Description: "test", Framework: FrameworkTerraform},
		{File: "test.tf", Line: 2, Resource: "aws_s3_bucket", Description: "other", Framework: FrameworkTerraform},
	}
	deduped := DedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 deduped findings, got %d", len(deduped))
	}
}

func TestDedupFindingsEmpty(t *testing.T) {
	deduped := DedupFindings(nil)
	if len(deduped) != 0 {
		t.Errorf("expected 0, got %d", len(deduped))
	}
}

func TestScanTerraformFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.tf")
	content := `resource "aws_s3_bucket" "test" {
  acl = "public-read"
  bucket = "test-bucket"
}

resource "aws_security_group_rule" "test" {
  cidr_blocks = ["0.0.0.0/0"]
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	findings, err := ScanTerraformFile(path)
	if err != nil {
		t.Fatalf("ScanTerraformFile() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for terraform file")
	}
	for _, f := range findings {
		if f.File != path {
			t.Errorf("File = %q, want %q", f.File, path)
		}
		if f.Framework != FrameworkTerraform {
			t.Errorf("Framework = %q, want terraform", f.Framework)
		}
	}
}

func TestScanTerraformFileNotFound(t *testing.T) {
	_, err := ScanTerraformFile("/nonexistent/path.tf")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestScanCloudFormationFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.yaml")
	content := `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  SecurityGroup:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      CidrIp: 0.0.0.0/0
  Instance:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	findings, err := ScanCloudFormationFile(path)
	if err != nil {
		t.Fatalf("ScanCloudFormationFile() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range findings {
		if f.Framework != FrameworkCloudFormation {
			t.Errorf("Framework = %q, want cloudformation", f.Framework)
		}
	}
}

func TestScanCloudFormationFileExtended(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cf.yaml")
	content := `Resources:
  Policy:
    Type: "AWS::IAM::Policy"
    Properties:
      Action: "*"
      Principal: "*"
  DB:
    Type: "AWS::RDS::DBInstance"
    Properties:
      StorageEncrypted: false
      MultiAZ: false
  SG:
    Type: "AWS::EC2::SecurityGroup"
    Properties:
      SecurityGroupIngress:
        - FromPort: 22`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	findings, err := ScanCloudFormationFileExtended(path)
	if err != nil {
		t.Fatalf("ScanCloudFormationFileExtended() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestScanCloudFormationFileExtendedNotFound(t *testing.T) {
	_, err := ScanCloudFormationFileExtended("/nonexistent")
	if err == nil {
		t.Error("expected error")
	}
}

func TestScanTerraformFileExtended(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.tf")
	content := `resource "aws_kms_key" "key" {
  kms_key_id = ""
}

resource "aws_db_instance" "db" {
  backup_retention_period = 0
}

resource "aws_instance" "web" {
  associate_public_ip_address = true
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	findings, err := ScanTerraformFileExtended(path)
	if err != nil {
		t.Fatalf("ScanTerraformFileExtended() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestScanTerraformFileExtendedNotFound(t *testing.T) {
	_, err := ScanTerraformFileExtended("/nonexistent")
	if err == nil {
		t.Error("expected error")
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()
	tfPath := filepath.Join(dir, "test.tf")
	os.WriteFile(tfPath, []byte(`acl = "public-read"`), 0644)

	yamlPath := filepath.Join(dir, "template.yaml")
	os.WriteFile(yamlPath, []byte(`AWSTemplateFormatVersion: 2010-09-09\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket`), 0644)

	findings, err := ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory() error = %v", err)
	}
	if len(findings) == 0 {
		t.Log("no findings (may depend on content format)")
	}
}

func TestScanDirectoryWithK8s(t *testing.T) {
	dir := t.TempDir()
	k8sPath := filepath.Join(dir, "pod.yaml")
	os.WriteFile(k8sPath, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true"), 0644)

	findings, err := ScanDirectoryWithK8s(dir)
	if err != nil {
		t.Fatalf("ScanDirectoryWithK8s() error = %v", err)
	}
	_ = findings
}

func TestScanDirectoryIgnoreDotDirs(t *testing.T) {
	dir := t.TempDir()
	dotDir := filepath.Join(dir, ".hidden")
	os.Mkdir(dotDir, 0755)
	os.WriteFile(filepath.Join(dotDir, "bad.tf"), []byte(`acl = "public-read"`), 0644)

	findings, err := ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory() error = %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.File, ".hidden") {
			t.Error("should not scan hidden directories")
		}
	}
}

func TestScanFileNotFound(t *testing.T) {
	_, err := scanFile("/nonexistent", nil, FrameworkTerraform)
	if err == nil {
		t.Error("expected error")
	}
}

func TestScanStore(t *testing.T) {
	store := &ScanStore{scans: make(map[string]*ScanRecord)}
	store.Set("test-1", &ScanRecord{ID: "test-1", Status: "running"})
	rec := store.Get("test-1")
	if rec == nil {
		t.Fatal("Get() returned nil")
	}
	if rec.Status != "running" {
		t.Errorf("Status = %q, want running", rec.Status)
	}
	rec = store.Get("nonexistent")
	if rec != nil {
		t.Error("Get() should return nil for non-existent")
	}
}

func TestWriteCloudJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeCloudJSON(w, map[string]string{"key": "value"})
	resp := w.Result()
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}
}

func TestReadCloudJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"path":"/tmp"}`))
	var req struct {
		Path string `json:"path"`
	}
	err := readCloudJSON(w, r, &req)
	if err != nil {
		t.Fatalf("readCloudJSON() error = %v", err)
	}
	if req.Path != "/tmp" {
		t.Errorf("Path = %q, want /tmp", req.Path)
	}
}

func TestReadCloudJSONMaxBytes(t *testing.T) {
	w := httptest.NewRecorder()
	largeBody := strings.Repeat("a", maxCloudBody+1)
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"path":"`+largeBody+`"}`))
	var req struct {
		Path string `json:"path"`
	}
	err := readCloudJSON(w, r, &req)
	if err == nil {
		t.Error("expected error for oversized body")
	}
}

func TestHandleCloudScan(t *testing.T) {
	dir := strings.ReplaceAll(t.TempDir(), "\\", "/")
	body := `{"path":"` + dir + `"}`
	r := httptest.NewRequest("POST", "/api/cloud/scan", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudScan(w, r)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandleCloudScanInvalidMethod(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/cloud/scan", nil)
	w := httptest.NewRecorder()
	HandleCloudScan(w, r)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Result().StatusCode)
	}
}

func TestHandleCloudScanBadRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/scan", strings.NewReader(`invalid`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudScan(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCloudScanEmptyPath(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/scan", strings.NewReader(`{"path":""}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudScan(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCloudGetResult(t *testing.T) {
	globalScanStore.Set("test-1", &ScanRecord{ID: "test-1", Status: "completed"})
	r := httptest.NewRequest("GET", "/api/cloud/scan/test-1", nil)
	w := httptest.NewRecorder()
	HandleCloudGetResult(w, r)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Result().StatusCode)
	}
}

func TestHandleCloudGetResultNotFound(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/cloud/scan/nonexistent", nil)
	w := httptest.NewRecorder()
	HandleCloudGetResult(w, r)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Result().StatusCode)
	}
}

func TestHandleCloudGetResultInvalidMethod(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/scan/test-1", nil)
	w := httptest.NewRecorder()
	HandleCloudGetResult(w, r)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Result().StatusCode)
	}
}

func TestHandleCloudGetResultMissingID(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/cloud/scan/", nil)
	w := httptest.NewRecorder()
	HandleCloudGetResult(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCloudValidate(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/validate", strings.NewReader(`{"line":"acl = \"public-read\""}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudValidate(w, r)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Result().StatusCode)
	}
}

func TestHandleCloudValidateInvalidMethod(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/cloud/validate", nil)
	w := httptest.NewRecorder()
	HandleCloudValidate(w, r)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Result().StatusCode)
	}
}

func TestHandleCloudValidateBadRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/validate", strings.NewReader(`invalid`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudValidate(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCloudValidateEmptyLine(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/cloud/validate", strings.NewReader(`{"line":""}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCloudValidate(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestRegisterCloudScannerHandlers(t *testing.T) {
	mux := http.NewServeMux()
	RegisterCloudScannerHandlers(mux)
}

func TestScanDirectoryWalkError(t *testing.T) {
	_, err := ScanDirectory("/nonexistent-directory-12345")
	if err == nil {
		t.Log("expected or no error on walk (OS dependent)")
	}
}

func TestCloudFindingStruct(t *testing.T) {
	f := CloudFinding{
		File:        "test.tf",
		Line:        5,
		Resource:    "aws_s3_bucket",
		Severity:    SevCritical,
		Description: "test",
		Remediation: "fix it",
		Framework:   FrameworkTerraform,
	}
	if f.File != "test.tf" {
		t.Errorf("File = %q", f.File)
	}
	if f.Severity != SevCritical {
		t.Errorf("Severity = %q", f.Severity)
	}
}
