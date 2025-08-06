//go:build windows

package server

import (
	"github.com/Microsoft/go-winio"
	"net"
	"os"
	"os/exec"
	"pssh/ssh_agent"
)

func createSocketListener() (net.Listener, error) {
	return winio.ListenPipe(ssh_agent.SocketPath(), nil)
}

func StartInBackground() error {
	cmd := exec.Command(os.Args[0], "mfa-agent")
	cmd.SysProcAttr = nil // Windows doesn't need detach
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	return cmd.Start()
}

func getNetworkType() string {
	return "winio"
}
