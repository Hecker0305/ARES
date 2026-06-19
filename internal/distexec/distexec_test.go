package distexec

import (
	"context"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	o := New(5)
	if o == nil {
		t.Fatal("expected non-nil orchestrator")
	}
}

func TestSubmit(t *testing.T) {
	o := New(3)
	task := &Task{
		ID:     "task-1",
		Type:   "scan",
		Target: "example.com",
	}
	err := o.Submit(task)
	if err != nil {
		t.Errorf("Submit error: %v", err)
	}
}

func TestSubmitBatch(t *testing.T) {
	o := New(3)
	tasks := []*Task{
		{ID: "t1", Type: "scan", Target: "a.com"},
		{ID: "t2", Type: "exploit", Target: "b.com"},
	}
	errs := o.SubmitBatch(tasks)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

func TestStart(t *testing.T) {
	o := New(2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Start(ctx)
}

func TestResults(t *testing.T) {
	o := New(3)
	ch := o.Results()
	if ch == nil {
		t.Error("expected non-nil results channel")
	}
}

func TestQueueSize(t *testing.T) {
	o := New(3)
	size := o.QueueSize()
	if size != 0 {
		t.Errorf("expected 0, got %d", size)
	}
}

func TestWorkers(t *testing.T) {
	o := New(4)
	workers := o.Workers()
	_ = workers
}

func TestStatus(t *testing.T) {
	o := New(2)
	status := o.Status()
	if status["total_workers"] != 2 {
		t.Errorf("expected 2 workers, got %v", status["total_workers"])
	}
}

func TestStartAndSubmit(t *testing.T) {
	o := New(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.Start(ctx)
	task := &Task{ID: "live-task", Type: "scan", Target: "target.com"}
	err := o.Submit(task)
	if err != nil {
		t.Logf("Submit error after start: %v", err)
	}
}

func TestTaskStruct(t *testing.T) {
	task := &Task{
		ID:       "test-task",
		Type:     "recon",
		Target:   "example.com",
		Priority: 10,
	}
	if task.ID != "test-task" {
		t.Errorf("expected test-task, got %s", task.ID)
	}
	if task.Priority != 10 {
		t.Errorf("expected 10, got %d", task.Priority)
	}
}

func TestConcurrency(t *testing.T) {
	o := New(5)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			o.Submit(&Task{ID: string(rune('0' + n)), Target: "t.com"})
		}(i)
	}
	wg.Wait()
}
