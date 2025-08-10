//go:build windows

package core

import (
	"os"
	"os/exec"
	"syscall"
)

func ProgramExec(program string, args []string, environ []string) error {
	cmd := exec.Command(program, args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = environ

	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}

	os.Exit(0) // terminate current process
	return nil
}
