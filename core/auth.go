package core

import (
	"encoding/json"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	authmodels "github.com/Kalybus/ark-sdk-golang/pkg/models/auth"
	"slices"
)

// DisplayAuthenticatedProfiles Show authenticated profiles and token duration
func displayAuthenticatedProfiles(tokensMap map[string]*authmodels.ArkToken) {
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
		parsedTime, err := ParseTokenDateString(tokenMap["expires_in"].(string))
		if err != nil {
			continue
		}
		args.PrintSuccess(fmt.Sprintf("Authenticated as %s until %s", tokenMap["username"], parsedTime))
	}
}

// IsAuthenticated Returns true if the authenticator is already authenticated
func (pssh *PSSH) isAuthenticated(authenticator auth.ArkAuth) bool {
	if !authenticator.IsAuthenticated(pssh.profile) {
		return false
	}
	_, err := authenticator.LoadAuthentication(pssh.profile, true)
	if err != nil {
		args.PrintNormal(fmt.Sprintf("%s Failed to refresh token, performing normal login [%s]",
			authenticator.AuthenticatorHumanReadableName(), err))
		return false
	}
	args.PrintSuccess(fmt.Sprintf("%s Authentication Refreshed",
		authenticator.AuthenticatorHumanReadableName()))
	return true
}

// Authenticate Performs user authentication using the ark profile
func (pssh *PSSH) Authenticate() error {
	/******************************************************************************************************
	 * Code is heavily based on func ArkLoginAction::runLoginAction(cmd *cobra.Command, loginArgs []string)
	 * at ark_login_action.go
	 ******************************************************************************************************/
	tokensMap := make(map[string]*authmodels.ArkToken)
	sharedSecretsMap := make(map[authmodels.ArkAuthMethod][][2]string)

	defer displayAuthenticatedProfiles(tokensMap)
	force := pssh.GetForceAuthenticationParam()
	for authenticatorName, authProfile := range pssh.profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		// Skip authentication if already authenticated
		if !force && pssh.isAuthenticated(authenticator) {
			tokensMap[authenticator.AuthenticatorHumanReadableName()] = authenticator.(*auth.ArkISPAuth).Token
			continue
		}
		// Skip unsupported authentication type: Unknown auth method or non-interactive authentication
		if !common.IsInteractive() || !slices.Contains(authmodels.ArkAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			continue
		}
		// Perform authentication
		authProfile.Username = pssh.AskUsername(authenticatorName)
		secret := &authmodels.ArkSecret{Secret: pssh.AskSecret(authenticatorName, sharedSecretsMap)}
		// Partially fixes a glitch when the user types Enter, the "Sent Mobile Authenticator request to your device..." appears again
		// The glitch is caused by the Ask.One(survey.Password{}) in the polling goroutine, which waits for a user input
		// SaveStdin and RestoreStdin help prevent the surveys to break the shell.
		stdin, t, err := SaveStdin()
		if err != nil {
			return fmt.Errorf("failed to save stdin before authentication: %s", err)
		}
		token, err := authenticator.Authenticate(pssh.profile, nil, secret, force, true)
		if err != nil {
			return fmt.Errorf("failed to authenticate with %s: %s", authenticator.AuthenticatorHumanReadableName(), err)
		}
		err = RestoreStdin(stdin, t)
		if err != nil {
			return fmt.Errorf("failed to restore stdin after authentication: %s", err)
		}
		// Store shared password for other authenticators
		noSharedSecrets := pssh.GetNoSharedSecretsParam()
		if !noSharedSecrets && slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) {
			sharedSecretsMap[authProfile.AuthMethod] = append(sharedSecretsMap[authProfile.AuthMethod], [2]string{authProfile.Username, secret.Secret})
		}
		tokensMap[authenticator.AuthenticatorHumanReadableName()] = token
	}
	return nil
}
