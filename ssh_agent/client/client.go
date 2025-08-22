package client

import (
	"crypto"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

type SSHAgentClient struct {
	logger *common.ArkLogger
}

func NewSSHAgentClient() *SSHAgentClient {
	logger := common.GetLogger("SSHAgentClient", common.Unknown)
	return &SSHAgentClient{
		logger: logger,
	}
}

// GetKeys lists all keys currently available in the SSH agent.
func (agentClient *SSHAgentClient) GetKeys() ([]*agent.Key, error) {
	conn, err := getAgentConnection()
	if err != nil {
		return nil, fmt.Errorf("could not connect to SSH agent: %w", err)
	}
	defer func(conn net.Conn) {
		err = conn.Close()
		if err != nil {
			agentClient.logger.Error("Failed to close SSH agent connection: %s", err)
			return
		}
	}(conn)

	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("could not list SSH keys: %w", err)
	}
	agentClient.logger.Debug("Retrieved %d keys from agent", len(keys))
	return keys, nil
}

// AddKey reads a private key from the disk and adds it to the SSH agent.
func (agentClient *SSHAgentClient) AddKey(name string, key string, lifetime uint32) error {
	var err error
	keyBytes := []byte(key)

	// Parse private key (handle passphrase prompting if encrypted)
	var parsedKey crypto.PrivateKey
	parsedKey, err = ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		agentClient.logger.Error("failed to parse private key: %s", err)
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	conn, err := getAgentConnection()
	if err != nil {
		agentClient.logger.Error("failed to connect to SSH agent: %s", err)
		return fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	defer func(conn net.Conn) {
		err = conn.Close()
		if err != nil {
			agentClient.logger.Error("failed to close SSH agent connection: %w", err)
		}
	}(conn)

	ag := agent.NewClient(conn)
	err = ag.Add(agent.AddedKey{
		PrivateKey:   parsedKey,
		Comment:      name,
		LifetimeSecs: lifetime,
	})
	if err != nil {
		agentClient.logger.Error("failed to add key to agent: %s", err)
		return fmt.Errorf("failed to add key to agent: %w", err)
	}
	agentClient.logger.Debug("Added key [%s] to agent", name)
	return nil
}

func (agentClient *SSHAgentClient) HasKey(keyName string) (bool, error) {
	agentKeys, err := agentClient.GetKeys()
	if err != nil {
		agentKeys = []*agent.Key{}
		agentClient.logger.Error("failed getting agent keys: %s", err)
		return false, fmt.Errorf("failed getting agent keys: %s", err)
	}
	// Search for existing keys in an agent
	for _, key := range agentKeys {
		if key.Comment == keyName {
			agentClient.logger.Debug("Found key [%s] in agent", keyName)
			return true, nil
		}
	}
	agentClient.logger.Debug("Fail to find key [%s] in agent", keyName)
	return false, nil
}
