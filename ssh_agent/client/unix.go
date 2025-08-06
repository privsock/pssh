//go:build !windows
// +build !windows

package client

import (
	"net"
	"pssh/ssh_agent"
)

func getAgentConnection() (net.Conn, error) {
	return net.Dial("unix", ssh_agent.SocketPath())
}
