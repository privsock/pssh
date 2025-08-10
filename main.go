package main

import (
	"pssh/cmd"
)

func main() {
	err := cmd.RootCmd.Execute()
	if err != nil {
		return
	}
}
