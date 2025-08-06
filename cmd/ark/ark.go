package ark

import (
	"github.com/Kalybus/ark-sdk-golang/pkg/actions"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
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
