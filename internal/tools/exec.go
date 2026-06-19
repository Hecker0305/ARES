package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/security"
)

func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	spec := security.CommandSpec{Binary: name, Args: args}
	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		return "", validated.Err
	}
	sbCfg := sandbox.Config{
		Level:      sandbox.SandboxBasic,
		Timeouts:   120 * time.Second,
		MaxOutput:  10 << 20,
		ReadOnly:   true,
		NetworkOff: false,
	}
	sb := sandbox.NewManager(sbCfg)
	result := sb.Execute(ctx, validated.Binary, validated.Args, nil)
	if result.Violation != "" {
		return "", fmt.Errorf("sandbox violation: %s", result.Violation)
	}
	if result.ExitCode != 0 {
		return result.Stdout, fmt.Errorf("command failed: %s", result.Stderr)
	}
	return result.Stdout, nil
}

type CommandError struct {
	Err    error
	Stderr string
}

func (e *CommandError) Error() string {
	return e.Err.Error() + ": " + e.Stderr
}
