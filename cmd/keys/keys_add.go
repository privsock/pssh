package keys

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	"os"
	"pssh/config"
	"pssh/core"
	sshagentclient "pssh/ssh_agent/client"
)

var (
	defaultLifetime uint32 = 3600
)

var keysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a key",
	Long:  `Add an ssh key to the agent`,
	Run:   AddMFAKey,
	Args:  cobra.ExactArgs(1),
}

func init() {
	keysAddCmd.Flags().String("profile-name", "", "profile name to load")
	keysAddCmd.Flags().String("username", "", "Name of the key user")
	keysAddCmd.Flags().Uint32P("lifetime", "l", 0, "Lifetime of the key (in seconds)")
}

// AddMFAKey adds a short-lived MFA-enabled SSH private key to the SSH agent.
func AddMFAKey(cmd *cobra.Command, execArgs []string) {
	pssh := core.NewPSSH(cmd, execArgs)
	username, err := pssh.GetUsername()
	lifetime := GetKeyLifetimeParam(cmd)
	keyPath := execArgs[0]
	key, err := os.ReadFile(keyPath)
	agentClient := sshagentclient.NewSSHAgentClient()
	err = agentClient.AddKey(username, string(key), lifetime)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Fail to add key: %v", err))
	}
	return
}

// GetKeyLifetimeParam retrieves the "lifetime" flag value from the provided command or defaults one hour.
func GetKeyLifetimeParam(cmd *cobra.Command) uint32 {
	lifetime, _ := cmd.Flags().GetUint32("lifetime")
	if lifetime == 0 {
		lifetime = config.GetUint32("key_lifetime")
	}
	if lifetime == 0 {
		lifetime = defaultLifetime
	}
	return lifetime
}
