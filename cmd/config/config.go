package config

import (
	"fmt"
	"github.com/Iilun/survey/v2"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Edit config",
	Long:  `Edit pssh configuration`,
	Run: func(cmd *cobra.Command, args []string) {
		ConfigureString("ark_profile", "Enter Ark profile name", "", false)
		ConfigureString("login_username", "Enter username", "", true)
		ConfigureString("sia_network", "Enter SIA preferred network (e.g default)", "default_network", false)
	},
}

func ConfigureString(key string, prompt string, defaultValue string, required bool) {
	var keyVal string
	var isRequired = true
	for keyVal == "" && isRequired {
		keyVal = viper.GetString(key)
		if keyVal == "" {
			keyVal = defaultValue
		}
		isRequired = required
		prompt := &survey.Input{
			Message: prompt,
			Default: keyVal,
		}
		err := survey.AskOne(prompt, &keyVal)

		//_, err := fmt.Scan(&keyVal)
		cobra.CheckErr(err)

		if keyVal != "" {
			viper.Set(key, keyVal)
			err = viper.WriteConfig()
		} else if isRequired {
			args.PrintFailure(fmt.Sprintf("Please enter a valid value for the %s", key))
		}
	}
}

func GetString(key string) string {
	return viper.GetString(key)
}

func GetProfileName() string {
	profile := viper.GetString("ark_profile")
	if profile == "" {
		profile = profiles.DefaultProfileName()
	}
	return profile
}

func init() {
}

// LoadConfig Load the user configuration (.pssh/config.json)
func LoadConfig() {
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

	// Create config file if it doesn't exist
	if _, err := os.Stat(path.Join(cfgDir, configName+"."+configType)); os.IsNotExist(err) {
		err = viper.SafeWriteConfig()
		cobra.CheckErr(err)
	}

	// Load viper variables from env
	viper.AutomaticEnv()

	// Load configuration file
	if err := viper.ReadInConfig(); err != nil {
		args.PrintFailure(fmt.Sprintf("Fail to read configuration file %s", viper.ConfigFileUsed()))
	}
}
