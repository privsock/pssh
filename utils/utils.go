package utils

import (
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"github.com/golang-jwt/jwt/v5"
	"os"
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
	authenticators := GetAuthenticators(profile, true)
	for _, authenticator := range authenticators {
		var ispAuth = authenticator.(*auth.ArkISPAuth)
		if ispAuth.Token.Token != "" {
			token = ispAuth.Token.Token
			break
		}
	}

	// Extract the subdomain from the token
	var subdomain string
	if token != "" {
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return "", err
		}
		claims := parsedToken.Claims.(jwt.MapClaims)
		if tokenSubdomain, ok := claims["subdomain"].(string); ok {
			subdomain = tokenSubdomain
		}
	}

	if subdomain == "" {
		// TODO Add subdomain to cmd parameters
		args.PrintFailure("Missing subdomain. Please provide a subdomain manually")
		return "", errors.New("missing subdomain")
	}

	return subdomain, nil
}
func GetUsername(profile *models.ArkProfile) (string, error) {
	var username string
	for _, authProfile := range profile.AuthProfiles {
		username = authProfile.Username
		break
	}
	if username == "" {
		args.PrintFailure("No username found")
		return "", errors.New("missing username")
	}
	return username, nil
}

func ParseTokenDateString(dateStr string) (string, error) {
	layout := time.RFC3339Nano
	parsedTime, err := time.Parse(layout, dateStr)
	if err != nil {
		fmt.Println("Error parsing time:", err)
		return "", errors.New("error parsing time")
	}

	localTime := parsedTime.Local()
	formatted := localTime.Format("2006-01-02 15:04:05")

	return formatted, nil
}
