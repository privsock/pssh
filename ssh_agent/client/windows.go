//go:build windows
// +build windows

package client

import (
	"github.com/Microsoft/go-winio"
	"net"
	"pssh/ssh_agent"
	"time"
)

// getAgentConnection connects to SSH agent using named pipe (on Windows)
func getAgentConnection() (net.Conn, error) {
	timeout := 2 * time.Second
	return winio.DialPipe(ssh_agent.SocketPath(), &timeout)
}
