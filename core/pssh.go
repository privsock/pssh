package core

import (
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth/identity"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	authmodels "github.com/Kalybus/ark-sdk-golang/pkg/models/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"pssh/config"
	"slices"
	"time"
)

type PSSH struct {
	profile *models.ArkProfile
	cmd     *cobra.Command
	Args    []string
	logger  *common.ArkLogger
	cache   *PSSHCache
}

type PSSHCache struct {
	authenticators map[authmodels.ArkAuthProfile]auth.ArkAuth
	subdomain      string
	username       string
}

// NewPSSH initializes and returns a pointer to a PSSH struct configured with the provided command and execution arguments.
func NewPSSH(cmd *cobra.Command, execArgs []string) *PSSH {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = GetProfileName()
	}
	profile := GetProfile(profileName)
	pssh := PSSH{
		profile: profile,
		cmd:     cmd,
		Args:    execArgs,
		logger:  common.GetLogger("PSSH", common.Unknown),
		cache:   &PSSHCache{},
	}
	return &pssh
}

// GetForceAuthenticationParam retrieves the value of the "force" flag and returns it as a boolean value.
func (pssh *PSSH) GetForceAuthenticationParam() bool {
	forceAuthentication, err := pssh.cmd.Flags().GetBool("force")
	if err != nil {
		pssh.logger.Error("Failed to get force flag: %s", err)
		return false
	}
	return forceAuthentication
}

// GetNoSharedSecretsParam retrieves the value of the "no-shared-secrets" flag and returns it as a boolean.
func (pssh *PSSH) GetNoSharedSecretsParam() bool {
	noSharedSecrets, err := pssh.cmd.Flags().GetBool("no-shared-secrets")
	if err != nil {
		pssh.logger.Error("Failed to get no-shared-secrets flag: %s", err)
		return false
	}
	return noSharedSecrets
}

/********************
 * Helper functions
 ********************/

// GetAuthenticators returns a list of authenticators for the profile
func (pssh *PSSH) GetAuthenticators(refreshAuth bool) map[authmodels.ArkAuthProfile]auth.ArkAuth {
	// Use cache if it exists
	if pssh.cache.authenticators != nil {
		return pssh.cache.authenticators
	}
	authenticators := make(map[authmodels.ArkAuthProfile]auth.ArkAuth)
	for authenticatorName, authProfile := range pssh.profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		token, err := authenticator.LoadAuthentication(pssh.profile, refreshAuth)
		if err != nil || token == nil {
			continue
		}
		if time.Now().After(time.Time(token.ExpiresIn)) {
			continue
		}
		pssh.logger.Debug("Found authenticator: %s", authenticator.AuthenticatorHumanReadableName())
		authenticators[*authProfile] = authenticator
	}
	pssh.cache.authenticators = authenticators
	return authenticators
}

// GetSubdomain returns the tenant subdomain (e.g., demo for tenant url demo.cyberark.cloud)
func (pssh *PSSH) GetSubdomain() (string, error) {
	// Use cache if it exists
	if pssh.cache.subdomain != "" {
		return pssh.cache.subdomain, nil
	}
	// Try extracting the subdomain from an authentication token
	authenticators := pssh.GetAuthenticators(true)
	for _, authenticator := range authenticators {
		var ispAuth = authenticator.(*auth.ArkISPAuth)
		if ispAuth.Token.Token != "" {
			parsedToken, _, err := new(jwt.Parser).ParseUnverified(ispAuth.Token.Token, jwt.MapClaims{})
			if err != nil {
				return "", err
			}
			claims := parsedToken.Claims.(jwt.MapClaims)
			if tokenSubdomain, ok := claims["subdomain"].(string); ok {
				config.Set("known_subdomain", tokenSubdomain) // Update known subdomain config
				pssh.logger.Debug("Extracted subdomain [%s] from authentication token [%s]", tokenSubdomain, authenticator.AuthenticatorHumanReadableName())
				pssh.cache.subdomain = tokenSubdomain
				return tokenSubdomain, nil
			}
		}
	}
	// Try using the last known subdomain (saved from last token extraction)
	knownSubdomain := config.GetString("known_subdomain")
	if knownSubdomain != "" {
		pssh.logger.Debug("Found subdomain [%s] in known_subdomain config", knownSubdomain)
		pssh.cache.subdomain = knownSubdomain
		return knownSubdomain, nil
	}
	// Fail to find the subdomain
	pssh.logger.Error("Subdomain not found in authentication token or known_subdomain config")
	return "", errors.New("missing subdomain")
}

// GetUsername retrieves the username from the authentication profiles. Returns an error if no username is found.
func (pssh *PSSH) GetUsername() (string, error) {
	if pssh.cache.username != "" {
		return pssh.cache.username, nil
	}
	var username string
	for authProfile, authenticator := range pssh.GetAuthenticators(true) {
		username = authProfile.Username
		if username != "" {
			pssh.logger.Debug("Found username [%s] of authenticator [%s]", username, authenticator.AuthenticatorHumanReadableName())
			pssh.cache.username = username
			return username, nil
		}
	}
	pssh.logger.Error("Username not found in authentication profiles")
	return "", errors.New("missing username")
}

// GetKeyName generates and returns a key name in the format "domain@username" or an error if retrieval fails.
func (pssh *PSSH) GetKeyName() (string, error) {
	username, err := pssh.GetUsername()
	if err != nil {
		pssh.logger.Error("Failed to get username: %s", err)
		return "", fmt.Errorf("failed to get username: %s", err)
	}
	domain, err := pssh.GetSubdomain()
	if err != nil {
		pssh.logger.Error("Failed to get domain: %s", err)
		return "", fmt.Errorf("failed to get domain: %s", err)
	}
	keyName := fmt.Sprintf("%s@%s", domain, username)
	pssh.logger.Debug("Using mfa key name [%s]", keyName)
	return keyName, nil
}

// AskUsername retrieves the username for the specified authenticator. If unavailable, prompts the user to input it interactively.
func (pssh *PSSH) AskUsername(authenticatorName string) string {
	authenticator := auth.SupportedAuthenticators[authenticatorName]
	username, _ := pssh.GetUsername()
	if username != "" {
		return username
	}
	username, _ = args.GetArg(
		pssh.cmd,
		fmt.Sprintf("%s-username", authenticatorName),
		fmt.Sprintf("%s Username", authenticator.AuthenticatorHumanReadableName()),
		"",
		false,
		true,
		false,
	)
	return username
}

// AskSecret retrieves a secret for the specified authenticator. It uses shared secrets, checks password requirements, or prompts interactively.
func (pssh *PSSH) AskSecret(authenticatorName string, sharedSecretsMap map[authmodels.ArkAuthMethod][][2]string) string {
	authProfile := pssh.profile.AuthProfiles[authenticatorName]
	authenticator := auth.SupportedAuthenticators[authenticatorName]

	// Get password: from shared secret
	if slices.Contains(authmodels.ArkAuthMethodSharableCredentials, authProfile.AuthMethod) &&
		len(sharedSecretsMap[authProfile.AuthMethod]) > 0 && !pssh.GetNoSharedSecretsParam() {
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
		pssh.cmd,
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
