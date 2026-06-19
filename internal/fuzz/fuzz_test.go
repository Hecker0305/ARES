package fuzz

import (
	"testing"
	"time"
)

func TestNewAdaptiveFuzzer(t *testing.T) {
	cfg := FuzzConfig{Mutations: 5, Concurrency: 2, Timeout: 5 * time.Second}
	f := NewAdaptiveFuzzer(cfg)
	if f == nil {
		t.Fatal("expected non-nil fuzzer")
	}
}

func TestMutateAdaptive(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{Mutations: 5})
	mutations := f.mutateAdaptive("test")
	if len(mutations) == 0 {
		t.Error("expected at least 1 mutation")
	}
}

func TestObfuscate(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{})
	result := f.obfuscate("test%value")
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestCaseSwap(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{})
	result := f.caseSwap("test")
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestNullByte(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{})
	result := f.nullByte("test")
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestLearnFromResponse(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{})
	f.LearnFromResponse("test-payload", "response ok", true)
	f.LearnFromResponse("bad-payload", "blocked", false)
}

func TestDetectWAF(t *testing.T) {
	f := NewAdaptiveFuzzer(FuzzConfig{WAFDetection: true})
	if !f.detectWAF("Cloudflare") {
		t.Log("expected Cloudflare detection")
	}
}
