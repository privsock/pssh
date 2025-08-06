//go:build windows

package ssh_agent

var pipePath = `\\.\pipe\pssh-agent`

func SocketPath() string {
	return pipePath
}
