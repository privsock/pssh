package keys

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"pssh/config"
	sshagentclient "pssh/ssh_agent/client"
	"pssh/utils"
)

var keysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a key",
	Long:  `Add an ssh key to the agent`,
	Run: func(cmd *cobra.Command, args []string) {
		err := AddMFAKey(cmd, args)
		if err != nil {
			return
		}
	},
	Args: cobra.ExactArgs(1),
}

func init() {
	keysAddCmd.Flags().String("profile-name", "", "Profile name to load")
	keysAddCmd.Flags().String("username", "", "Name of the key user")
	keysAddCmd.Flags().Uint32P("duration", "d", 0, "Duration of the key (in seconds)")
}

func AddMFAKey(cmd *cobra.Command, execArgs []string) error {
	profileName, _ := cmd.Flags().GetString("profile-name")
	username, _ := cmd.Flags().GetString("username")
	keyPath := execArgs[0]
	duration, _ := cmd.Flags().GetUint32("duration")

	if profileName == "" {
		profileName = config.GetString("ark_profile")
	}
	if username == "" {
		username = config.GetString("login_username")
	}
	if username == "" {
		profile := utils.GetProfile(profileName)
		var err error
		username, err = utils.GetUsername(profile)
		if err != nil {
			return fmt.Errorf("missing username for sia key: %s", err)
		}
	}
	if duration == 0 {
		duration = config.GetUint32("key_lifetime")
	}
	if duration == 0 {
		duration = 3600
	}
	key, err := os.ReadFile(keyPath)
	err = sshagentclient.AddKey(username, string(key), duration)
	if err != nil {
		return err
	}
	return nil
}
