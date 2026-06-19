package pivot

import (
	"testing"
)

func testRouter(t *testing.T) *PivotRouter {
	t.Helper()
	r, err := NewPivotRouter(PivotConfig{User: "test", Password: "test"})
	if err != nil {
		t.Fatalf("NewPivotRouter: %v", err)
	}
	return r
}

func TestNewPivotRouter(t *testing.T) {
	cfg := PivotConfig{SOCKS5Host: "localhost", SOCKS5Port: 9050, User: "test", Password: "test"}
	r, err := NewPivotRouter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestNewPivotRouterNoCreds(t *testing.T) {
	cfg := PivotConfig{}
	_, err := NewPivotRouter(cfg)
	if err == nil {
		t.Fatal("expected error with missing credentials")
	}
}

func TestAddAndRemoveRoute(t *testing.T) {
	r := testRouter(t)
	route, err := r.AddRoute("target.com")
	if err != nil {
		t.Fatalf("AddRoute error: %v", err)
	}
	if route.TargetHost != "target.com" {
		t.Errorf("expected target.com, got %s", route.TargetHost)
	}
	err = r.RemoveRoute(route.ID)
	if err != nil {
		t.Errorf("RemoveRoute error: %v", err)
	}
}

func TestRouteFor(t *testing.T) {
	r := testRouter(t)
	r.AddRoute("example.com")
	route := r.RouteFor("example.com")
	if route == nil {
		t.Fatal("expected route")
	}
	if route.TargetHost != "example.com" {
		t.Errorf("expected example.com, got %s", route.TargetHost)
	}
}

func TestRouteForNonexistent(t *testing.T) {
	r := testRouter(t)
	route := r.RouteFor("nonexistent")
	if route != nil {
		t.Error("expected nil")
	}
}

func TestActive(t *testing.T) {
	r := testRouter(t)
	if r.Active() {
		t.Error("expected not active initially")
	}
}

func TestViaPivot(t *testing.T) {
	cmd := ViaPivot("nmap -sV target", nil)
	if cmd != "nmap -sV target" {
		t.Errorf("expected unchanged command, got %s", cmd)
	}
	route := &PivotRoute{SOCKS5Addr: "socks5://localhost:9050", ViaSOCKS5: true}
	proxied := ViaPivot("curl http://target", route)
	if proxied != "ALL_PROXY=socks5://localhost:9050 curl http://target" {
		t.Errorf("expected proxied command, got %s", proxied)
	}
}
