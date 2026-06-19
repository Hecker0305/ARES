package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/ares/engine/internal/security"
)

type TerminalConfig struct {
	Workdir    string
	Timeout    time.Duration
	Env        map[string]string
	ScopeCheck func(cmd string) error
}

type CommandResult struct {
	Command   string
	Stdout    string
	Stderr    string
	ExitCode  int
	TimedOut  bool
	StartTime time.Time
	EndTime   time.Time
}

func (r *CommandResult) Summary() string {
	elapsed := r.EndTime.Sub(r.StartTime)
	status := "OK"
	if r.ExitCode != 0 {
		status = "FAIL"
	}
	if r.TimedOut {
		status = "TIMEOUT"
	}
	return fmt.Sprintf("[%s] %s [exit=%d elapsed=%v]", status, r.Stdout, r.ExitCode, elapsed)
}

func ExecuteCommand(ctx context.Context, spec security.CommandSpec, cfg TerminalConfig) (string, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}

	if cfg.ScopeCheck != nil {
		fullCmd := spec.Binary
		for _, a := range spec.Args {
			fullCmd += " " + a
		}
		if err := cfg.ScopeCheck(fullCmd); err != nil {
			return "", fmt.Errorf("scope denied: %w", err)
		}
	}

	if kernel := security.GetK(); true {
		verdict := kernel.ValidateAction(ctx, security.ActionRequest{
			Type:   security.ActionShellExec,
			Binary: spec.Binary,
			Args:   spec.Args,
			Source: "agent.ExecuteCommand",
		})
		if verdict.Decision != security.DecisionAllow {
			return "", fmt.Errorf("kernel denied execution: %s", verdict.Reason)
		}
	}

	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		return "", fmt.Errorf("command rejected: %w", validated.Err)
	}

	execCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	execCmd := exec.CommandContext(execCtx, validated.Binary, validated.Args...)

	if cfg.Workdir != "" {
		execCmd.Dir = cfg.Workdir
	}

	execCmd.Env = make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		execCmd.Env = append(execCmd.Env, k+"="+v)
	}
	safeEnv := security.SecureEnvVars()
	for k, v := range safeEnv {
		execCmd.Env = append(execCmd.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- execCmd.Run()
	}()

	select {
	case <-execCtx.Done():
		if execCmd.Process != nil {
			execCmd.Process.Kill()
		}
		<-done
		return "", execCtx.Err()
	case err := <-done:
		output := stdout.String()
		if err != nil {
			if stderr.Len() > 0 {
				output += "\n[STDERR] " + stderr.String()
			}
		}
		return output, err
	}
}

func RunWithOutput(ctx context.Context, spec security.CommandSpec, workdir string, timeout time.Duration) *CommandResult {
	start := time.Now()
	cfg := TerminalConfig{
		Workdir: workdir,
		Timeout: timeout,
	}
	output, err := ExecuteCommand(ctx, spec, cfg)
	result := &CommandResult{
		Command:   spec.Binary,
		Stdout:    output,
		StartTime: start,
		EndTime:   time.Now(),
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.TimedOut = true
		} else {
			result.ExitCode = 1
		}
	}
	return result
}
