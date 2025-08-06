package keys

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	sshagentclient "pssh/ssh_agent/client"
)

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List keys",
	Long:  `List ssh keys in ssh agent`,
	Run: func(cmd *cobra.Command, execArgs []string) {
		err := ListKeys()
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Fail to list keys: %s", err))
			return
		}
	},
	Args: cobra.NoArgs,
}

func ListKeys() error {
	keys, err := sshagentclient.GetKeys()
	if err != nil {
		return fmt.Errorf("error getting keys: %s", err)
	}
	for i, key := range keys {
		fmt.Printf("Key %d: %s (%s)\n", i+1, key.Comment, key.Format)
	}
	return nil
}
