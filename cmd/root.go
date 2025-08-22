package cmd

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	"pssh/cmd/ark"
	configCmd "pssh/cmd/config"
	"pssh/cmd/keys"
	"pssh/cmd/mfa_agent"
	"pssh/config"
	"pssh/core"
	"pssh/ssh_agent"
	sshagentclient "pssh/ssh_agent/client"
	sshagentserver "pssh/ssh_agent/server"
	"time"
)

var RootCmd = &cobra.Command{
	Use:     "pssh user@address",
	Version: "0.3.0",
	Short:   "pssh is an ssh connection client for the CyberArk platform",
	Run:     rootCmdEntrypoint,
	Args:    cobra.ExactArgs(1),
}

// init Initializes the root command configuration. Automatically ran at initialization
func init() {
	RootCmd.PersistentFlags().Bool("verbose", false, "Whether to verbose log")
	RootCmd.PersistentFlags().String("logger-style", "default", "Which verbose logger style to use")
	RootCmd.PersistentFlags().String("log-level", "INFO", "Log level to use while verbose")

	RootCmd.Flags().String("profile-name", "", "profile name to load")
	RootCmd.Flags().String("network", "", "SIA network name")
	RootCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	RootCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	RootCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")

	RootCmd.AddCommand(configCmd.ConfigCmd)
	RootCmd.AddCommand(keys.KeysCmd)
	RootCmd.AddCommand(ark.ArkCmd)
	RootCmd.AddCommand(mfa_agent.MfaAgentCmd)
}

// rootCmdEntrypoint Authenticate and performs SSH connection
func rootCmdEntrypoint(cmd *cobra.Command, execArgs []string) {
	logger := common.GetLogger("Root", common.Unknown)
	pssh := core.NewPSSH(cmd, execArgs)
	agentServer := sshagentserver.NewSSHAgentServer()
	agentClient := sshagentclient.NewSSHAgentClient()
	if !agentServer.IsRunning() {
		err := sshagentserver.StartInBackground()
		if err != nil {
			args.PrintFailure("Fail to start MFA agent")
			return
		}
		args.PrintSuccess(fmt.Sprintf("MFA agent started at %s", ssh_agent.SocketPath()))
		time.Sleep(100 * time.Millisecond) // Wait for the agent to start
	}
	keyName, err := pssh.GetKeyName()
	if err != nil {
		logger.Error("Failed getting key name: %v", err)
		return
	}
	foundKeys, err := agentClient.HasKey(keyName)
	if err != nil {
		logger.Error("Failed checking for existing keys: %v", err)
		return
	}
	if !foundKeys { // Using a bool here crashes the debugger somehow...
		err = pssh.Authenticate()
		if err != nil {
			args.PrintWarning(fmt.Sprintf("Failed to authenticate: %s", err))
		}
		// Update keyName after authentication
		keyName, err = pssh.GetKeyName()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed getting key name: %s\n", err))
		}
		// Generate a new key
		var key string
		key, err = pssh.GenerateSIAMFAKey()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to generate sia key: %s", err))
			return
		}
		// Load key to ssh agent
		lifetime := config.GetUint32("key_lifetime")
		if lifetime == 0 {
			lifetime = 900
		}
		err = agentClient.AddKey(keyName, key, lifetime)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed add sia key: %s", err))
		}
		logger.Info("SIA mfa key added to the agent")
	}

	err = pssh.ConnectWithSIA()
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to connect: %s", err))
		return
	}
}
