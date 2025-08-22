package server

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"pssh/ssh_agent"
)

type SSHAgentServer struct {
	logger *common.ArkLogger
}

func NewSSHAgentServer() *SSHAgentServer {
	logger := common.GetLogger("SSHAgentClient", common.Unknown)
	return &SSHAgentServer{
		logger: logger,
	}
}

func (agentServer *SSHAgentServer) Start() error {
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

	nativeAgent := agent.NewKeyring()
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
					agentServer.logger.Error("Close failed: %v", err)
					return
				}
			}(c)
			_ = agent.ServeAgent(nativeAgent, c)
		}(conn)
	}
}

func (agentServer *SSHAgentServer) IsRunning() bool {
	addr := ssh_agent.SocketPath()
	conn, err := net.Dial(getNetworkType(), addr)
	if err != nil {
		agentServer.logger.Error("Failed to connect to SSH agent: %s", err)
		return false
	}
	err = conn.Close()
	if err != nil {
		agentServer.logger.Error("Failed to close SSH agent connection: %s", err)
		return false
	}
	agentServer.logger.Debug("SSH agent is running on %s", addr)
	return true
}
