package security

import (
	"testing"
)

func TestValidateCommand_EmptyBinary(t *testing.T) {
	result := ValidateCommand(CommandSpec{Binary: ""})
	if result.Err == nil {
		t.Error("expected error for empty binary")
	}
}

func TestValidateCommand_RelativePath(t *testing.T) {
	result := ValidateCommand(CommandSpec{Binary: "./malicious", Args: nil})
	if result.Err == nil {
		t.Error("expected error for relative path binary")
	}
}

func TestValidateCommand_AbsolutePath(t *testing.T) {
	result := ValidateCommand(CommandSpec{Binary: "/usr/bin/curl", Args: nil})
	if result.Err == nil {
		t.Error("expected error for absolute path binary (use name only)")
	}
}

func TestValidateCommand_UnknownBinary(t *testing.T) {
	result := ValidateCommand(CommandSpec{Binary: "nonexistent_binary_xyz", Args: nil})
	if result.Err == nil {
		t.Error("expected error for unknown binary")
	}
}

func TestValidateCommand_ControlCharInArg(t *testing.T) {
	result := ValidateCommand(CommandSpec{Binary: "curl", Args: []string{"-o", "/tmp/test\x00"}})
	if result.Err == nil {
		t.Error("expected error for control character in argument")
	}
}

func TestSanitizeInput_NullBytes(t *testing.T) {
	input := "test\x00command"
	result := SanitizeInput(input)
	if result != "testcommand" {
		t.Errorf("expected testcommand, got %s", result)
	}
}

func TestSanitizeFilename_PathTraversal(t *testing.T) {
	_, err := SanitizeFilename("../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal in filename")
	}
}

func TestSanitizeFilename_InvalidChars(t *testing.T) {
	_, err := SanitizeFilename("test/file.txt")
	if err == nil {
		t.Error("expected error for slash in filename")
	}
}

func TestValidateTarget_PrivateIP(t *testing.T) {
	err := ValidateTarget("192.168.1.1")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestValidateTarget_PublicIP(t *testing.T) {
	err := ValidateTarget("8.8.8.8")
	if err != nil {
		t.Errorf("unexpected error for public IP: %v", err)
	}
}

func TestValidateTarget_Loopback(t *testing.T) {
	err := ValidateTarget("127.0.0.1")
	if err == nil {
		t.Error("expected error for loopback")
	}
}

func TestValidateHostForSSRF_Metadata(t *testing.T) {
	err := ValidateHostForSSRF("169.254.169.254")
	if err == nil {
		t.Error("expected error for metadata IP")
	}
}

func TestValidateHostForSSRF_Valid(t *testing.T) {
	err := ValidateHostForSSRF("example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
