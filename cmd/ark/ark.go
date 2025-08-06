package ark

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/actions"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"runtime"
)

var ArkCmd = &cobra.Command{
	Use:   "ark",
	Short: "Ark commands",
	//Run: func(cmd *cobra.Command, args []string) {
	//	commonargs.PrintFailure("Please choose an action (e.g. configure)")
	//},
	Args: cobra.NoArgs,
}

func init() {
	if runtime.GOOS == "windows" {
		setHomeFromDiskAndDir()
	}
	profilesLoader := profiles.DefaultProfilesLoader()
	arkActions := []actions.ArkAction{
		actions.NewArkProfilesAction(profilesLoader),
		actions.NewArkConfigureAction(profilesLoader),
		actions.NewArkCacheAction(),
	}
	for _, action := range arkActions {
		action.DefineAction(ArkCmd)
	}
}

func setHomeFromDiskAndDir() error {
	if os.Getenv("HOME") != "" {
		// HOME already set, do nothing
		return nil
	}

	homeDisk := os.Getenv("HOMEDRIVE")
	homeDir := os.Getenv("HOMEPATH")

	if homeDisk == "" || homeDir == "" {
		return fmt.Errorf("HOMEDRIVE or HOMEPATH not set")
	}

	home := filepath.Clean(filepath.Join(homeDisk, homeDir))
	return os.Setenv("HOME", home)
}
