package utils

import (
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/term"
	"os"
	"os/exec"
	"pssh/config"
	"runtime"
	"strings"
	"time"
)

// GetProfile Returns the stored profile from the name (e.g. ark)
func GetProfile(profileName string) *models.ArkProfile {
	profileLoader := profiles.DefaultProfilesLoader()
	profile, err := (*profileLoader).LoadProfile(profiles.DeduceProfileName(profileName))
	if err != nil || profile == nil {
		args.PrintFailure("Please configure a profile before trying to login")
		os.Exit(1)
	}
	return profile
}

// GetAuthenticators Returns a list of authenticators for the profile
func GetAuthenticators(profile *models.ArkProfile, refreshAuth bool) []auth.ArkAuth {
	var authenticators []auth.ArkAuth
	for authenticatorName := range profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		token, err := authenticator.LoadAuthentication(profile, refreshAuth)
		if err != nil || token == nil {
			continue
		}
		if time.Now().After(time.Time(token.ExpiresIn)) {
			continue
		}
		authenticators = append(authenticators, authenticator)
	}
	return authenticators
}

// GetSubdomain Returns the tenant subdomain (e.g. demo for tenant url demo.cyberark.cloud)
func GetSubdomain(profile *models.ArkProfile) (string, error) {
	// Find an authentication token
	var token string
	authenticators := GetAuthenticators(profile, false)
	for _, authenticator := range authenticators {
		var ispAuth = authenticator.(*auth.ArkISPAuth)
		if ispAuth.Token.Token != "" {
			token = ispAuth.Token.Token
			break
		}
	}

	// Extract the subdomain from the token
	if token != "" {
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return "", err
		}
		claims := parsedToken.Claims.(jwt.MapClaims)
		if tokenSubdomain, ok := claims["subdomain"].(string); ok {
			config.Set("known_subdomain", tokenSubdomain)
			return tokenSubdomain, nil
		}
	}

	// Extract last known domain
	knownSubdomain := config.GetString("known_subdomain")
	if knownSubdomain != "" {
		return knownSubdomain, nil
	}

	// TODO Add subdomain to cmd parameters
	return "", errors.New("missing subdomain")
}

func GetUsername(profile *models.ArkProfile) (string, error) {
	var username string
	for _, authProfile := range profile.AuthProfiles {
		username = authProfile.Username
		break
	}
	if username == "" {
		return "", errors.New("missing username")
	}
	return username, nil
}

func GetKeyName(profile *models.ArkProfile) (string, error) {
	username, err := GetUsername(profile)
	if err != nil {
		return "", fmt.Errorf("failed to get username: %s", err)
	}
	domain, err := GetSubdomain(profile)
	if err != nil {
		return "", fmt.Errorf("failed to get domain: %s", err)
	}
	keyName := fmt.Sprintf("%s@%s", domain, username)
	return keyName, nil
}

func ParseTokenDateString(dateStr string) (string, error) {
	layout := time.RFC3339Nano
	parsedTime, err := time.Parse(layout, dateStr)
	if err != nil {
		return "", fmt.Errorf("error parsing time: %s", err)
	}

	localTime := parsedTime.Local()
	formatted := localTime.Format("2006-01-02 15:04:05")

	return formatted, nil
}

func SaveStdin() (int, *term.State, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return fd, nil, err
	}
	return fd, state, nil
}

func RestoreStdin(fd int, state *term.State) error {
	err := term.Restore(fd, state)
	if err != nil {
		return err
	}
	return nil
}

func AddOrUpdateEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func DetectSSHPath() (string, error) {
	// Try to find 'ssh' in PATH first
	path, err := exec.LookPath("ssh")
	if err == nil {
		return path, nil
	}

	// Fallbacks by OS (rarely needed if PATH is set correctly)
	switch runtime.GOOS {
	case "windows":
		// On Windows, ssh.exe might be in System32 or in Git installation
		// Common fallback locations (adjust as needed)
		possiblePaths := []string{
			`C:\Windows\System32\OpenSSH\ssh.exe`,
			`C:\Program Files\Git\usr\bin\ssh.exe`,
		}
		for _, p := range possiblePaths {
			if _, err := exec.LookPath(p); err == nil {
				return p, nil
			}
		}
	case "darwin":
		// macOS typical location (usually covered by PATH)
		possiblePaths := []string{
			"/usr/bin/ssh",
			"/usr/local/bin/ssh",
		}
		for _, p := range possiblePaths {
			if _, err := exec.LookPath(p); err == nil {
				return p, nil
			}
		}
	case "linux":
		// Linux typical locations
		possiblePaths := []string{
			"/usr/bin/ssh",
			"/bin/ssh",
			"/usr/local/bin/ssh",
		}
		for _, p := range possiblePaths {
			if _, err := exec.LookPath(p); err == nil {
				return p, nil
			}
		}
	}

	return "", fmt.Errorf("ssh binary not found")
}
