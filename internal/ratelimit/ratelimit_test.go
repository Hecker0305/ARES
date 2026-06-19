package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	l := New(10.0, 20)
	if l == nil {
		t.Error("New() returned nil")
	}
	if l.refillHz != 10.0 {
		t.Errorf("refillHz = %v, want 10.0", l.refillHz)
	}
	if l.maxToken != 20 {
		t.Errorf("maxToken = %v, want 20", l.maxToken)
	}
}

func TestLimiter_TryAcquire(t *testing.T) {
	l := New(10.0, 5)

	if !l.TryAcquire() {
		t.Error("TryAcquire() should succeed on first call")
	}
	if !l.TryAcquire() {
		t.Error("TryAcquire() should succeed on second call")
	}
}

func TestLimiter_TryAcquire_Exhausted(t *testing.T) {
	l := New(0.1, 1)
	l.TryAcquire()

	if l.TryAcquire() {
		t.Error("TryAcquire() should fail when tokens exhausted")
	}
}

func TestLimiter_Wait(t *testing.T) {
	l := New(100.0, 1)

	start := time.Now()
	l.Wait()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Wait() took too long: %v", elapsed)
	}
}

func TestLimiter_Concurrency(t *testing.T) {
	l := New(1000.0, 100)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Wait()
		}()
	}
	wg.Wait()
}

func TestPresets(t *testing.T) {
	stealth := Stealth()
	if stealth.refillHz != 1.0 {
		t.Errorf("Stealth() refillHz = %v, want 1.0", stealth.refillHz)
	}

	normal := Normal()
	if normal.refillHz != 10.0 {
		t.Errorf("Normal() refillHz = %v, want 10.0", normal.refillHz)
	}

	aggressive := Aggressive()
	if aggressive.refillHz != 50.0 {
		t.Errorf("Aggressive() refillHz = %v, want 50.0", aggressive.refillHz)
	}
}
