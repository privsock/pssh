package server

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"pssh/ssh_agent"
)

func Start() error {
	listener, err := createSocketListener()
	if err != nil {
		return fmt.Errorf("Failed to create socket: %v", err)
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to close listener: %v", err))
		}
	}(listener)
	args.PrintSuccess(fmt.Sprintf("Agent listening on %s", ssh_agent.SocketPath()))

	agentServer := agent.NewKeyring()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer func(c net.Conn) {
				err = c.Close()
				if err != nil {
					args.PrintFailure(fmt.Sprintf("Close failed: %v", err))
				}
			}(c)
			_ = agent.ServeAgent(agentServer, c)
		}(conn)
	}
}

func IsRunning() bool {
	addr := ssh_agent.SocketPath()
	conn, err := net.Dial(getNetworkType(), addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
