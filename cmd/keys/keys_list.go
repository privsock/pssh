package keys

import (
	"fmt"
	"github.com/spf13/cobra"
	"pssh/ssh_agent"
)

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List keys",
	Long:  `List ssh keys in ssh agent`,
	Run: func(cmd *cobra.Command, args []string) {
		ListKeys()
	},
	Args: cobra.NoArgs,
}

func ListKeys() {
	keys, err := ssh_agent.GetKeys()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for i, key := range keys {
		fmt.Printf("Key %d: %s (%s)\n", i+1, key.Comment, key.Format)
	}
}
