//go:build !windows

package bridge

import (
	"os/exec"
	"syscall"
)

func configurePlatformCmd(cmd *exec.Cmd) {}

func bindKillOnCloseJob(pid int) (func() error, error) {
	return func() error { return nil }, nil
}

func sendGracefulStop(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}
