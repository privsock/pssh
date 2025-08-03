package config

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Edit config",
	Long:  `Edit pssh configuration`,
	Run: func(cmd *cobra.Command, args []string) {
		configureString("login_username", "Enter username")
	},
}

func configureString(key string, prompt string) {
	keyVal := viper.GetString(key)
	if keyVal != "" {
		fmt.Print(prompt + " (" + keyVal + "): ")
	} else {
		fmt.Print(prompt + ": ")
	}
	_, err := fmt.Scan(&keyVal)
	cobra.CheckErr(err)

	if keyVal != "" {
		viper.Set(key, keyVal)
		err = viper.WriteConfig()
	}
}

func init() {
}
