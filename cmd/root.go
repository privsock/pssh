package cmd

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"
	"pssh/cmd/ark"
	"pssh/cmd/config"
	"pssh/cmd/keys"
	"pssh/ssh_agent"
	"pssh/utils"
)

var RootCmd = &cobra.Command{
	Use:     "pssh user@address",
	Version: "0.2.0",
	Short:   "pssh is an ssh connection client for the CyberArk platform",
	Run:     rootCmdEntrypoint,
	Args:    cobra.ExactArgs(1),
}

// init Initialize the root command configuration. Automatically ran at initialization
func init() {
	RootCmd.Flags().String("profile-name", "", "Profile name to load")
	RootCmd.Flags().String("network", "", "SIA network name")
	RootCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	RootCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	RootCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")

	RootCmd.AddCommand(config.ConfigCmd)
	RootCmd.AddCommand(keys.KeysCmd)
	RootCmd.AddCommand(ark.ArkCmd)
}

// rootCmdEntrypoint Authenticate and performs SSH connection
func rootCmdEntrypoint(cmd *cobra.Command, execArgs []string) {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = config.GetProfileName()
	}
	profile := utils.GetProfile(profileName)
	pssh := PSSH{
		profile: profile,
		cmd:     cmd,
		args:    execArgs,
	}

	if !FoundMfaKey(profile) { // Using a bool here crashes the debugger somehow...
		args.PrintWarning("Authentication required")
		err := pssh.Authenticate()
		if err != nil {
			args.PrintWarning(fmt.Sprintf("Profile %s failed to authenticate, %s", profileName, err))
		}

		// Update keyName after authentication
		var keyName string
		keyName, err = utils.GetKeyName(profile)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed getting key name: %s\n", err))
		}

		// Generate a new key
		var key string
		key, err = pssh.GenerateSSHToken()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to generate mfa key: %s", err))
			return
		}

		// Load key to ssh agent
		lifetime := config.GetUint32("key_lifetime")
		if lifetime == 0 {
			lifetime = 900
		}
		err = ssh_agent.AddKey(keyName, key, lifetime)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed add mfa key: %s", err))
		}
		fmt.Println("SSH key added to agent")
	}

	err := pssh.ConnectWithSIA()
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to connect: %s", err))
		return
	}
}

func FoundMfaKey(profile *models.ArkProfile) bool {
	agentKeys, err := ssh_agent.GetKeys()
	if err != nil {
		agentKeys = []*agent.Key{}
		args.PrintFailure(fmt.Sprintf("Failed getting agent keys: %s", err))
	}
	if len(agentKeys) == 0 {
		args.PrintWarning("No keys found in SSH agent")
	}
	keyName, err := utils.GetKeyName(profile)
	if err == nil {
		// Search for existing keys in agent
		for _, key := range agentKeys {
			if key.Comment == keyName {
				return true
			}
		}
	}
	return false
}
