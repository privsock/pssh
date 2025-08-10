package config

import (
	"fmt"
	"github.com/Iilun/survey/v2"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path"
	"strconv"
)

func init() {
	cobra.OnInitialize(LoadConfig)
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

// Set Set a value in the pssh config
func Set(key string, value any) {
	viper.Set(key, value)
	err := viper.WriteConfig()
	cobra.CheckErr(err)
}

// GetString Get a string value from the pssh config
func GetString(key string) string {
	return viper.GetString(key)
}

// SetString Set a string value in the pssh config
func SetString(key string, prompt string, defaultValue string, required bool) {
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

// SetUint32 Set a uint32 value in the pssh config
func SetUint32(key string, prompt string, defaultValue uint32, required bool) {
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

// GetUint32 Get a uint32 value in the pssh config
func GetUint32(key string) uint32 {
	return viper.GetUint32(key)
}
