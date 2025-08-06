//go:build windows
// +build windows

package ssh_agent

import (
	"fmt"
	"net"

	"github.com/ActiveState/termtest/agentsocket"
)

// winOpenAgent connects to SSH agent using named pipe (on Windows)
func winOpenAgent() (net.Conn, error) {
	conn, err := agentsocket.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Windows SSH agent: %w", err)
	}
	return conn, nil
}
