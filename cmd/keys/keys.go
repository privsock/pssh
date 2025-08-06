package keys

import (
	"github.com/spf13/cobra"
)

var KeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List mfa ssh keys",
	Long:  `List the mfa caching keys in the agent`,
	Args:  cobra.NoArgs,
}

func init() {
	KeysCmd.AddCommand(keysListCmd)
	KeysCmd.AddCommand(keysAddCmd)
}
