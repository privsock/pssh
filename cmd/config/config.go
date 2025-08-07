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
	"strconv"
)

var ConfigCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure pssh",
	Long:  "Configure pssh",
	Run: func(cmd *cobra.Command, args []string) {
		ConfigureString("ark_profile", "Enter Ark profile name", "", false)
		ConfigureString("login_username", "Enter username", "", true)
		ConfigureString("sia_network", "Enter SIA preferred network (e.g default)", "default_network", false)
		ConfigureUint32("key_lifetime", "Enter the sia mfa key lifetime in seconds (e.g 900)", 900, false)
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
		cobra.CheckErr(err)

		if keyVal != "" {
			Set(key, keyVal)
		} else if isRequired {
			args.PrintFailure(fmt.Sprintf("Please enter a valid value for the %s", key))
		}
	}
}

func Set(key string, value any) {
	viper.Set(key, value)
	err := viper.WriteConfig()
	cobra.CheckErr(err)
}

func ConfigureUint32(key string, prompt string, defaultValue uint32, required bool) {
	var keyVal uint32
	var isRequired = true
	for keyVal == 0 && isRequired {
		keyVal = viper.GetUint32(key)
		if keyVal == 0 {
			keyVal = defaultValue
		}
		isRequired = required
		prompt := &survey.Input{
			Message: prompt,
			Default: strconv.FormatUint(uint64(keyVal), 10),
		}
		err := survey.AskOne(prompt, &keyVal)
		cobra.CheckErr(err)

		if keyVal != 0 {
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

func GetUint32(key string) uint32 {
	return viper.GetUint32(key)
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
