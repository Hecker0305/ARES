package timing

import (
	"testing"
	"time"
)

func TestNewTimingProfile(t *testing.T) {
	tp := NewTimingProfile()
	if tp == nil {
		t.Fatal("expected non-nil profile")
	}
}

func TestElapsed(t *testing.T) {
	tp := NewTimingProfile()
	time.Sleep(time.Millisecond)
	e := tp.Elapsed()
	if e <= 0 {
		t.Error("expected positive elapsed time")
	}
}

func TestReset(t *testing.T) {
	tp := NewTimingProfile()
	time.Sleep(time.Millisecond)
	tp.Reset()
	e := tp.Elapsed()
	if e > time.Millisecond {
		t.Error("expected small elapsed after reset")
	}
}
