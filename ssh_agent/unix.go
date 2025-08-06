//go:build !windows

package ssh_agent

import (
	"os"
	"path"
)

var sockFile = path.Join(os.TempDir(), "pssh-agent.sock")

func SocketPath() string {
	return sockFile
}
