package config

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
	psshConfig "pssh/config"
)

var ConfigCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure pssh",
	Long:  "Configure pssh",
	Run: func(cmd *cobra.Command, execArgs []string) {
		profilesLoader := profiles.DefaultProfilesLoader()
		loadedProfiles, err := (*profilesLoader).LoadAllProfiles()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to load profiles: %v", err))
			return
		}
		if len(loadedProfiles) == 0 {
			args.PrintFailure("No profiles were found. Please run `pssh ark configure`")
			return
		}
		profilesNames := []string{}
		for _, profile := range loadedProfiles {
			profilesNames = append(profilesNames, profile.ProfileName)
		}
		psshConfig.AskStringChoice("ark_profile", "Choose the Ark profile to use", profilesNames, "")
		psshConfig.AskStringChoice("ssh_service", "Select the SSH service to use", []string{"sia", "psmp"}, "sia")
		sshService := psshConfig.GetString("ssh_service")
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
