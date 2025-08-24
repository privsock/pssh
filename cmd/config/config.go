package config

import (
	"fmt"
	"github.com/Iilun/survey/v2"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	psshConfig "pssh/config"
)

var ConfigCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure pssh",
	Long:  "Configure pssh",
	Run: func(cmd *cobra.Command, execArgs []string) {
		psshConfig.AskString("ark_profile", "Enter Ark profile name", "", false)
		sshServicePrompt := &survey.Select{
			Message: "Select SSH service",
			Options: []string{"sia", "psmp"},
			Default: "sia",
		}
		var sshService string
		err := survey.AskOne(sshServicePrompt, &sshService)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Fail to configure pssh: %s", err))
			return
		}
		psshConfig.Set("ssh_service", sshService)
		if sshService == "sia" {
			psshConfig.AskString("sia_network", "Enter SIA preferred network (e.g default)", "default_network", false)
			psshConfig.AskUint32("key_lifetime", "Enter the sia mfa key lifetime in seconds (e.g 900)", 900, false)
		}
		if sshService == "psmp" {
			psshConfig.AskString("psmp_host", "Enter psmp host", "", true)
			psshConfig.AskUint32("psmp_port", "Enter psmp port", 22, true)
		}
	},
}
