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
	"pssh/cmd/mfa_agent"
	sshagentclient "pssh/ssh_agent/client"
	sshagentserver "pssh/ssh_agent/server"
	"pssh/utils"
)

var RootCmd = &cobra.Command{
	Use:     "pssh user@address",
	Version: "0.2.1",
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
	RootCmd.AddCommand(mfa_agent.MfaAgentCmd)
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

	if !sshagentserver.IsRunning() {
		err := sshagentserver.StartInBackground()
		if err != nil {
			//args.PrintFailure("Fail to start MFA agent")
			return
		} else {
			//args.PrintSuccess("SIA SSH agent started")
		}
	}

	foundKeys, err := FoundMfaKey(profile)
	if err != nil {
		// TODO Debug failing to fetch an mfa key
	}
	if !foundKeys { // Using a bool here crashes the debugger somehow...
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
			args.PrintFailure(fmt.Sprintf("Failed to generate sia key: %s", err))
			return
		}

		// Load key to ssh agent
		lifetime := config.GetUint32("key_lifetime")
		if lifetime == 0 {
			lifetime = 900
		}
		err = sshagentclient.AddKey(keyName, key, lifetime)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed add sia key: %s", err))
		}
		//args.PrintSuccess("SIA key added to mfa agent")
	}

	err = pssh.ConnectWithSIA()
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to connect: %s", err))
		return
	}
}

func FoundMfaKey(profile *models.ArkProfile) (bool, error) {
	agentKeys, err := sshagentclient.GetKeys()
	if err != nil {
		agentKeys = []*agent.Key{}
		return false, fmt.Errorf("failed getting agent keys: %s", err)
	}
	keyName, err := utils.GetKeyName(profile)
	if err == nil {
		// Search for existing keys in agent
		for _, key := range agentKeys {
			if key.Comment == keyName {
				return true, nil
			}
		}
	}
	return false, nil
}
