package cmd

import (
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path"
	"pssh/cmd/config"
	"pssh/cmd/version"
	"pssh/utils"
)

var RootCmd = &cobra.Command{
	Use:     "pssh",
	Version: "0.1.0",
	Short:   "pssh is an ssh wrapper integrating with CyberArk platform",
	Run:     rootCmdEntrypoint,
	Args:    cobra.ExactArgs(1),
}

// init Initialize the root command configuration. Automatically ran at initialization
func init() {
	cobra.OnInitialize(loadConfig)
	RootCmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name to load")
	RootCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	RootCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	RootCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")
	RootCmd.AddCommand(version.VersionCmd)
	RootCmd.AddCommand(config.ConfigCmd)
}

// rootCmdEntrypoint Authenticate and performs SSH connection
func rootCmdEntrypoint(cmd *cobra.Command, execArgs []string) {
	profileName, _ := cmd.Flags().GetString("profile-name")
	pssh := PSSH{
		profile: utils.GetProfile(profileName),
		logger:  common.GetLogger("PSSH", common.Unknown),
	}

	err := pssh.Authenticate(cmd)
	if err != nil {
		return
	}
	sshKeyPath := pssh.GenerateSSHToken(cmd)
	err = pssh.ConnectWithSSH(cmd, execArgs, sshKeyPath)
	if err != nil {
		args.PrintFailure("Failed to connect")
		return
	}
}

// loadConfig Load the user configuration (.pssh/config.json)
func loadConfig() {
	configPath := ".pssh"
	configName := "config"
	configType := "json"

	// Create config dir in $HOME
	home, err := os.UserHomeDir()
	cobra.CheckErr(err)
	cfgDir := path.Join(home, configPath)
	if _, err := os.Stat(cfgDir); os.IsNotExist(err) {
		err := os.MkdirAll(cfgDir, 0770)
		cobra.CheckErr(err)
	}

	viper.AddConfigPath(cfgDir)
	viper.SetConfigType(configType)
	viper.SetConfigName(configName)

	// Create config file if not exist
	if _, err := os.Stat(path.Join(cfgDir, configName+"."+configType)); os.IsNotExist(err) {
		err = viper.SafeWriteConfig()
		cobra.CheckErr(err)
	}

	// Load viper variables from env
	viper.AutomaticEnv()

	// Load configuration file
	if err := viper.ReadInConfig(); err == nil {
		//fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
