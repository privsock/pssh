//go:build !windows
// +build !windows

package ssh_agent

import (
	"fmt"
	"net"
	"os"
)

func getAgentConnection() (net.Conn, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	return net.Dial("unix", socket)
}
