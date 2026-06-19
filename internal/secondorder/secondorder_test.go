package secondorder

import (
	"testing"
)

func TestNewCorrelationEngine(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	if ce == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestGenerateToken(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	t1, err := ce.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	t2, err := ce.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if t1 == t2 {
		t.Error("expected unique tokens")
	}
	if len(t1) < 8 {
		t.Errorf("expected token length >= 8, got %d", len(t1))
	}
}

func TestRegisterAndCheck(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	token := ce.Register("http://target.com/login", "username", "' OR '1'='1", "sqli")
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if ce.CheckTrigger(token) {
		t.Error("expected not triggered initially")
	}
	ce.Trigger(token)
	if !ce.CheckTrigger(token) {
		t.Error("expected triggered after Trigger()")
	}
}

func TestInject(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	token := ce.Register("http://target.com", "param", "payload", "xss")
	injected := ce.Inject(token)
	if injected == "" {
		t.Error("expected non-empty injected string")
	}
}

func TestListPending(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	ce.Register("http://target.com/a", "p1", "v1", "sqli")
	pending := ce.ListPending()
	_ = pending
}

func TestCleanup(t *testing.T) {
	ce := NewCorrelationEngine("http://oob.local")
	ce.Register("http://target.com", "p", "v", "sqli")
	ce.Cleanup()
}

func TestNewPayloadBuilder(t *testing.T) {
	pb := NewPayloadBuilder("sqli", "' OR '1'='1")
	if pb == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestPayloadBuilderBuild(t *testing.T) {
	pb := NewPayloadBuilder("sqli", "' OR '1'='1")
	pb = pb.WithToken("test-token")
	pb = pb.WithBaseURL("http://target.com")
	result := pb.Build()
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestIsSecondOrderVuln(t *testing.T) {
	_ = IsSecondOrderVuln("sqli")
	_ = IsSecondOrderVuln("xss")
	_ = IsSecondOrderVuln("unknown")
}
