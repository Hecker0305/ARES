//go:build !windows

package scanctx

import (
	"os/exec"
	"syscall"
)

func killCmd(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			syscall.Kill(-pgid, syscall.SIGKILL)
		}
		cmd.Process.Kill()
	}
}
