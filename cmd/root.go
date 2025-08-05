package cmd

import (
	"github.com/Kalybus/ark-sdk-golang/pkg/actions"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
	"pssh/cmd/config"
	"pssh/utils"
)

var RootCmd = &cobra.Command{
	Use:     "pssh user@address",
	Version: "0.1.5",
	Short:   "pssh is an ssh connection client for the CyberArk platform",
	Run:     rootCmdEntrypoint,
	Args:    cobra.ExactArgs(1),
}

// init Initialize the root command configuration. Automatically ran at initialization
func init() {
	cobra.OnInitialize(config.LoadConfig)
	RootCmd.Flags().String("profile-name", "", "Profile name to load")
	RootCmd.Flags().String("network", "", "SIA network name")
	RootCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	RootCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	RootCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")
	RootCmd.AddCommand(config.ConfigCmd)

	profilesLoader := profiles.DefaultProfilesLoader()
	arkActions := []actions.ArkAction{
		actions.NewArkProfilesAction(profilesLoader),
		actions.NewArkConfigureAction(profilesLoader),
		actions.NewArkCacheAction(),
	}

	for _, action := range arkActions {
		action.DefineAction(RootCmd)
	}
}

// rootCmdEntrypoint Authenticate and performs SSH connection
func rootCmdEntrypoint(cmd *cobra.Command, execArgs []string) {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = config.GetProfileName()
	}
	pssh := PSSH{
		profile: utils.GetProfile(profileName),
		cmd:     cmd,
		args:    execArgs,
	}

	err := pssh.Authenticate()
	if err != nil {
		return
	}
	err = pssh.ConnectWithSIA(pssh.GenerateSSHToken())
	if err != nil {
		args.PrintFailure("Failed to connect")
		return
	}
}
