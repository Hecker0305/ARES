//go:build windows

package scanctx

import (
	"fmt"
	"os/exec"
)

func killCmd(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
		cmd.Process.Kill()
	}
}
