package main

import (
	"github.com/spf13/cobra"
	"pssh/cmd"
	"pssh/cmd/config"
)

func main() {
	cobra.OnInitialize(config.LoadConfig)
	err := cmd.RootCmd.Execute()
	if err != nil {
		return
	}
}
