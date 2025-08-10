package core

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
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/sia/sso"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"pssh/config"
	"pssh/ssh_agent"
	"pssh/utils"
	"slices"
)

type PSSH struct {
	Profile *models.ArkProfile
	Cmd     *cobra.Command
	Args    []string
}

/********************
 * ISP Authentication
 ********************/

func NewPSSH(cmd *cobra.Command, execArgs []string) *PSSH {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = GetProfileName()
	}
	profile := utils.GetProfile(profileName)
	pssh := PSSH{
		Profile: profile,
		Cmd:     cmd,
		Args:    execArgs,
	}
	return &pssh
}

func GetProfileName() string {
	profile := config.GetString("ark_profile")
	if profile == "" {
		profile = profiles.DefaultProfileName()
	}
	return profile
}

// AskUsername Fetch user from configuration file or ask for username interactively
func (pssh *PSSH) AskUsername(authenticatorName string) string {
	authenticator := auth.SupportedAuthenticators[authenticatorName]
	username := config.GetString("login_username")
	if username != "" {
		return username
	}
	username, _ = args.GetArg(
		pssh.Cmd,
		fmt.Sprintf("%s-username", authenticatorName),
		fmt.Sprintf("%s Username", authenticator.AuthenticatorHumanReadableName()),
		"",
		false,
		true,
		false,
	)
	return username
}

// AskSecret Fetch secret from configuration file or ask for password interactively
func (pssh *PSSH) AskSecret(authenticatorName string, sharedSecretsMap map[authmodels.ArkAuthMethod][][2]string) string {
	authProfile := pssh.Profile.AuthProfiles[authenticatorName]
	authenticator := auth.SupportedAuthenticators[authenticatorName]

	// Get password: from shared secret
	if slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) &&
		len(sharedSecretsMap[authProfile.AuthMethod]) > 0 && !viper.GetBool("no-shared-secrets") {
		for _, s := range sharedSecretsMap[authProfile.AuthMethod] {
			if s[0] == authProfile.Username {
				return s[1]
			}
		}
	}
	// Get password: no password authentication factor
	if authenticatorName == "isp" && authProfile.AuthMethod == authmodels.Identity &&
		!identity.IsPasswordRequired(authProfile.Username,
			authProfile.AuthMethodSettings.(*authmodels.IdentityArkAuthMethodSettings).IdentityURL,
			authProfile.AuthMethodSettings.(*authmodels.IdentityArkAuthMethodSettings).IdentityTenantSubdomain) {
		return ""
	}
	// Get password: Interactively
	secretStr, err := args.GetArg(
		pssh.Cmd,
		fmt.Sprintf("%s-secret", authenticatorName),
		fmt.Sprintf("%s Secret", authenticator.AuthenticatorHumanReadableName()),
		"",
		true,
		false,
		false,
	)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to get %s secret: %s", authenticatorName, err))
		return ""
	}

	return secretStr
}

// DisplayAuthenticatedProfiles Show authenticated profiles and token duration
func (pssh *PSSH) DisplayAuthenticatedProfiles(tokensMap map[string]*authmodels.ArkToken) {
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
			continue
		}
		parsedTime, err := utils.ParseTokenDateString(tokenMap["expires_in"].(string))
		if err != nil {
			continue
		}
		args.PrintSuccess(fmt.Sprintf("Authenticated as %s until %s", tokenMap["username"], parsedTime))
	}
}

// IsAuthenticated Returns true if the authenticator is already authenticated
func (pssh *PSSH) IsAuthenticated(authenticator auth.ArkAuth) bool {
	refreshToken, _ := pssh.Cmd.Flags().GetBool("refresh-auth")
	if !authenticator.IsAuthenticated(pssh.Profile) {
		return false
	}
	if !refreshToken {
		return true
	}
	_, err := authenticator.LoadAuthentication(pssh.Profile, true)
	if err != nil {
		args.PrintNormal(fmt.Sprintf("%s Failed to refresh token, performing normal login [%s]",
			authenticator.AuthenticatorHumanReadableName(), err))
		return false
	}
	args.PrintSuccess(fmt.Sprintf("%s Authentication Refreshed",
		authenticator.AuthenticatorHumanReadableName()))
	return true
}

func (pssh *PSSH) Authenticate() error {
	return pssh.AuthenticateArk()
}

func (pssh *PSSH) AuthenticateOIDC() error {
	return nil
}

// Authenticate Perform user authentication using the ark profile
func (pssh *PSSH) AuthenticateArk() error {
	/******************************************************************************************************
	 * Code is heavily based on func ArkLoginAction::runLoginAction(cmd *cobra.Command, loginArgs []string)
	 * at ark_login_action.go
	 ******************************************************************************************************/
	tokensMap := make(map[string]*authmodels.ArkToken)
	sharedSecretsMap := make(map[authmodels.ArkAuthMethod][][2]string)

	defer pssh.DisplayAuthenticatedProfiles(tokensMap)
	force, _ := pssh.Cmd.Flags().GetBool("force")
	refreshAuth, _ := pssh.Cmd.Flags().GetBool("refresh-auth")
	for authenticatorName, authProfile := range pssh.Profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		/* Skip authentication if already authenticated */
		if !force && pssh.IsAuthenticated(authenticator) {
			tokensMap[authenticator.AuthenticatorHumanReadableName()] = authenticator.(*auth.ArkISPAuth).Token
			continue
		}
		/* Skip unsupported authentication type: Unknown auth method or non-interactive authentication */
		if !common.IsInteractive() || !slices.Contains(authmodels.ArkAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			continue
		}
		/* Perform user authentication */
		authProfile.Username = pssh.AskUsername(authenticatorName)
		secret := &authmodels.ArkSecret{Secret: pssh.AskSecret(authenticatorName, sharedSecretsMap)}
		// Partially fixes a glitch when the user types Enter, the "Sent Mobile Authenticator request to your device..." appears again
		// The glitch is caused by the Ask.One(survey.Password{}) in the polling goroutine, which waits for a user input
		// SaveStdin and RestoreStdin help prevent the surveys to break the shell.
		stdin, t, err := utils.SaveStdin()
		if err != nil {
			return fmt.Errorf("failed to save stdin before authentication: %s", err)
		}
		token, err := authenticator.Authenticate(pssh.Profile, nil, secret, force, refreshAuth)
		if err != nil {
			return fmt.Errorf("failed to authenticate with %s: %s", authenticator.AuthenticatorHumanReadableName(), err)
		}
		err = utils.RestoreStdin(stdin, t)
		if err != nil {
			return fmt.Errorf("failed to restore stdin after authentication: %s", err)
		}
		/* Store shared password for other authenticators */
		noSharedSecrets, _ := pssh.Cmd.Flags().GetBool("no-shared-secrets")
		if !noSharedSecrets && slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) {
			sharedSecretsMap[authProfile.AuthMethod] = append(sharedSecretsMap[authProfile.AuthMethod], [2]string{authProfile.Username, secret.Secret})
		}
		tokensMap[authenticator.AuthenticatorHumanReadableName()] = token
	}
	return nil
}

/***************
 * SIA Functions
 ***************/

// GenerateSSHToken Create an SSO service from the authenticator
func (pssh *PSSH) GenerateSSHToken() (string, error) {
	refreshAuth, _ := pssh.Cmd.Flags().GetBool("refresh-auth")

	authenticators := utils.GetAuthenticators(pssh.Profile, refreshAuth)
	ssoService, err := sso.NewArkSIASSOService(authenticators...)
	if err != nil {
		cobra.CheckErr(err)
		os.Exit(1)
	}

	// Generate a short-lived password for RDP
	path, err := os.MkdirTemp("", "pssh-mfa-*")
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to remove temporary directory: %s", err))
		}
	}(path)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %s", err)
	}
	sshKeyPath, err := ssoService.ShortLivedSSHKey(
		&ssomodels.ArkSIASSOGetSSHKey{
			Folder: path,
		})
	key, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ssh key file: %s", err)
	}
	return string(key), nil
}

// ConnectWithSIA Start an ssh connection using keypath
func (pssh *PSSH) ConnectWithSIA() error {
	cmdArgs := []string{"-o", "IdentityFile=none"}
	username, err := utils.GetUsername(pssh.Profile)
	if err != nil {
		return err
	}
	subdomain, err := utils.GetSubdomain(pssh.Profile)
	if err != nil {
		return err
	}
	if len(pssh.Args) == 0 {
		return errors.New("missing [user@]hostname")
	}
	content := pssh.Args[0]
	host := fmt.Sprintf("%s.ssh.cyberark.cloud", subdomain)
	network, err := pssh.Cmd.Flags().GetString("network")
	if err != nil {
		return errors.New("missing network")
	}
	if network == "" {
		network = config.GetString("sia_network")
	}
	if network != "" {
		network = fmt.Sprintf("#%s", network)
	}

	// ZSP: <username>@<login_suffix>#<subdomain>@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	// VTL: <username>@<login_suffix>#<subdomain>@<target_user>#account_domain@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	connString := fmt.Sprintf("%s#%s@%s%s@%s", username, subdomain, content, network, host)
	cmdArgs = append(cmdArgs, connString)
	err = pssh.Connect(cmdArgs)
	if err != nil {
		return nil
	}
	return nil
}

// Connect Connects using the system ssh client
func (pssh *PSSH) Connect(cmdArgs []string) error {
	sysArgs := []string{"ssh"}
	sysArgs = append(sysArgs, cmdArgs...)
	// TODO Detect ssh path dynamically

	sshPath, err := utils.DetectSSHPath()
	if err != nil {
		return fmt.Errorf("failed to detect ssh path: %s", err)
	}
	environ := utils.AddOrUpdateEnv(os.Environ(), "SSH_AUTH_SOCK", ssh_agent.SocketPath())
	ProgramExec(sshPath, sysArgs, environ)
	return nil
}
