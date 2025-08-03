package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth/identity"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	authmodels "github.com/Kalybus/ark-sdk-golang/pkg/models/auth"
	ssomodels "github.com/Kalybus/ark-sdk-golang/pkg/models/services/sia/sso"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/sia/sso"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"os/exec"
	"pssh/utils"
	"slices"
)

type PSSH struct {
	profile *models.ArkProfile
	logger  *common.ArkLogger
}

// Authenticate Perform user authentication using the ark profile
func (pssh *PSSH) Authenticate(cmd *cobra.Command) error {
	/* ****************************************************************************************************
	 * Code is heavily based on func ArkLoginAction::runLoginAction(cmd *cobra.Command, loginArgs []string)
	 * at ark_login_action.go
	 ******************************************************************************************************/
	sharedSecretsMap := make(map[authmodels.ArkAuthMethod][][2]string)
	tokensMap := make(map[string]*authmodels.ArkToken)

	for authenticatorName, authProfile := range pssh.profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		force, _ := cmd.Flags().GetBool("force")
		refreshAuth, _ := cmd.Flags().GetBool("refresh-auth")
		if authenticator.IsAuthenticated(pssh.profile) && !force {
			if refreshAuth {
				_, err := authenticator.LoadAuthentication(pssh.profile, true)
				if err == nil {
					args.PrintSuccess(
						fmt.Sprintf("%s Authentication Refreshed", authenticator.AuthenticatorHumanReadableName()))
					continue
				}
				pssh.logger.Info(
					fmt.Sprintf("%s Failed to refresh token, performing normal login [%s]",
						authenticator.AuthenticatorHumanReadableName(), err))
			} else {
				args.PrintSuccess(fmt.Sprintf("%s Already Authenticated",
					authenticator.AuthenticatorHumanReadableName()))
				continue
			}
		}
		secretStr, _ := cmd.Flags().GetString(fmt.Sprintf("%s-secret", authenticatorName))
		secret := &authmodels.ArkSecret{Secret: secretStr}
		userName, _ := cmd.Flags().GetString(fmt.Sprintf("%s-username", authenticatorName))
		if userName == "" {
			userName = authProfile.Username
		}
		if common.IsInteractive() && slices.Contains(authmodels.ArkAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			var err error
			authProfile.Username, err = args.GetArg(
				cmd,
				fmt.Sprintf("%s-username", authenticatorName),
				fmt.Sprintf("%s Username", authenticator.AuthenticatorHumanReadableName()),
				userName,
				false,
				true,
				false,
			)
			if slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) &&
				len(sharedSecretsMap[authProfile.AuthMethod]) > 0 && !viper.GetBool("no-shared-secrets") {
				for _, s := range sharedSecretsMap[authProfile.AuthMethod] {
					if s[0] == authProfile.Username {
						secret = &authmodels.ArkSecret{Secret: s[1]}
						break
					}
				}
			} else {
				if authenticatorName == "isp" &&
					authProfile.AuthMethod == authmodels.Identity &&
					!identity.IsPasswordRequired(authProfile.Username,
						authProfile.AuthMethodSettings.(*authmodels.IdentityArkAuthMethodSettings).IdentityURL,
						authProfile.AuthMethodSettings.(*authmodels.IdentityArkAuthMethodSettings).IdentityTenantSubdomain) {
					secret = &authmodels.ArkSecret{Secret: ""}
				} else {
					secretStr, err = args.GetArg(
						cmd,
						fmt.Sprintf("%s-secret", authenticatorName),
						fmt.Sprintf("%s Secret", authenticator.AuthenticatorHumanReadableName()),
						secretStr,
						true,
						false,
						false,
					)
					if err != nil {
						args.PrintFailure(fmt.Sprintf("Failed to get %s secret: %s", authenticatorName, err))
						return err
					}
					secret = &authmodels.ArkSecret{Secret: secretStr}
				}
			}
		} else if !common.IsInteractive() && slices.Contains(authmodels.ArkAuthMethodsRequireCredentials, authProfile.AuthMethod) && secret.Secret == "" {
			args.PrintFailure(fmt.Sprintf("%s-secret argument is required if authenticating to %s", authenticatorName, authenticator.AuthenticatorHumanReadableName()))
			return errors.New("missing secret argument")
		}

		token, err := authenticator.Authenticate(pssh.profile, nil, secret, force, refreshAuth)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to authenticate with %s: %s", authenticator.AuthenticatorHumanReadableName(), err))
			return err
		}

		noSharedSecrets, _ := cmd.Flags().GetBool("no-shared-secrets")
		if !noSharedSecrets && slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) {
			sharedSecretsMap[authProfile.AuthMethod] = append(sharedSecretsMap[authProfile.AuthMethod], [2]string{authProfile.Username, secret.Secret})
		}
		tokensMap[authenticator.AuthenticatorHumanReadableName()] = token
	}

	for _, v := range tokensMap {
		if v.Metadata != nil {
			if _, ok := v.Metadata["cookies"]; ok {
				delete(v.Metadata, "cookies")
			}
		}
		tokenMap := make(map[string]interface{})
		data, _ := json.Marshal(v)
		err := json.Unmarshal(data, &tokenMap)
		if err != nil {
			args.PrintFailure("Failed to parse token")
			return err
		}

		parsedTime, err := utils.ParseTokenDateString(tokenMap["expires_in"].(string))
		if err != nil {
			//args.PrintSuccess(fmt.Sprintf("Authenticated as %s", tokenMap["username"]))
			args.PrintFailure("Failed to parse username")
			return err
		}
		args.PrintSuccess(fmt.Sprintf("\nAuthenticated as %s until %s", tokenMap["username"], parsedTime))
	}
	return nil
}

// GenerateSSHToken Create an SSO service from the authenticator above
func (pssh *PSSH) GenerateSSHToken(cmd *cobra.Command) string {
	refreshAuth, _ := cmd.Flags().GetBool("refresh-auth")

	authenticators := utils.GetAuthenticators(pssh.profile, refreshAuth)
	ssoService, err := sso.NewArkSIASSOService(authenticators...)
	if err != nil {
		cobra.CheckErr(err)
		os.Exit(1)
	}

	// Generate a short-lived password for RDP
	sshKeyPath, err := ssoService.ShortLivedSSHKey(
		&ssomodels.ArkSIASSOGetSSHKey{},
	)
	return sshKeyPath
}

func (pssh *PSSH) GetUsername(cmd *cobra.Command) (string, error) {
	var username string
	for authenticatorName, authProfile := range pssh.profile.AuthProfiles {
		username, _ = cmd.Flags().GetString(fmt.Sprintf("%s-username", authenticatorName))
		if username == "" {
			username = authProfile.Username
		}
	}
	if username == "" {
		args.PrintFailure("No username found")
		return "", errors.New("missing username")
	}
	return username, nil
}

func (pssh *PSSH) ConnectWithSSH(cmd *cobra.Command, execArgs []string, keyPath string) error {
	cmdArgs := []string{"-i", keyPath, "-o", "IdentitiesOnly=yes"}
	username, err := pssh.GetUsername(cmd)
	if err != nil {
		return err
	}
	subdomain, err := utils.GetSubdomain(pssh.profile)
	if err != nil {
		return err
	}
	if len(execArgs) == 0 {
		return errors.New("missing [user@]hostname")
	}
	content := execArgs[0]
	host := fmt.Sprintf("%s.ssh.cyberark.cloud", subdomain)

	network, err := cmd.Flags().GetString("network")
	if err != nil {
		return errors.New("missing network")
	}
	network = fmt.Sprintf("#%s", network)

	// ZSP: <username>@<login_suffix>#<subdomain>@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	// VTL: <username>@<login_suffix>#<subdomain>@<target_user>#account_domain@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	connString := fmt.Sprintf("%s#%s@%s%s@%s", username, subdomain, content, network, host)
	cmdArgs = append(cmdArgs, connString)

	// Prepare command
	sshCmd := exec.Command("ssh", cmdArgs...)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdin = os.Stdin

	// SSH connection
	err = sshCmd.Run()
	if err != nil {
		return err
	}
	return nil
}
