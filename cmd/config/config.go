package config

import (
	"github.com/spf13/cobra"
	psshConfig "pssh/config"
)

var ConfigCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure pssh",
	Long:  "Configure pssh",
	Run: func(cmd *cobra.Command, args []string) {
		psshConfig.SetString("ark_profile", "Enter Ark profile name", "", false)
		psshConfig.SetString("sia_network", "Enter SIA preferred network (e.g default)", "default_network", false)
		psshConfig.SetUint32("key_lifetime", "Enter the sia mfa key lifetime in seconds (e.g 900)", 900, false)
	},
}
