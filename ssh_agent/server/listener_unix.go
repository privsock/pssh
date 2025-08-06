//go:build !windows

package server

import (
	"net"
	"os"
	"os/exec"
	"pssh/ssh_agent"
	"syscall"
)

func createSocketListener() (net.Listener, error) {
	_ = os.Remove(ssh_agent.SocketPath())
	return net.Listen("unix", ssh_agent.SocketPath())
}

func StartInBackground() error {
	cmd := exec.Command(os.Args[0], "mfa-agent")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	return cmd.Start()
}

func getNetworkType() string {
	return "unix"
}
