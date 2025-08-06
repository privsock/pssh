package ssh_agent

import (
	"crypto"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

// GetKeys lists all keys currently available in the SSH agent.
func GetKeys() ([]*agent.Key, error) {
	conn, err := getAgentConnection()
	if err != nil {
		return nil, fmt.Errorf("could not connect to SSH agent: %w", err)
	}
	defer conn.Close()

	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("could not list SSH keys: %w", err)
	}
	return keys, nil
}

// AddKey reads a private key from disk and adds it to the SSH agent.
func AddKey(name string, key string, lifetime uint32) error {
	var err error
	keyBytes := []byte(key)

	// Parse private key (handle passphrase prompting if encrypted)
	var parsedKey crypto.PrivateKey
	parsedKey, err = ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	conn, err := getAgentConnection()
	if err != nil {
		return fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	defer func(conn net.Conn) {
		err = conn.Close()
		if err != nil {
			fmt.Errorf("failed to close SSH agent connection: %w", err)
		}
	}(conn)

	ag := agent.NewClient(conn)
	err = ag.Add(agent.AddedKey{
		PrivateKey:   parsedKey,
		Comment:      name,
		LifetimeSecs: lifetime,
	})
	if err != nil {
		return fmt.Errorf("failed to add key to agent: %w", err)
	}
	return nil
}
