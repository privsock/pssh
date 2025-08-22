package core

import (
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/Kalybus/ark-sdk-golang/pkg/models"
	"github.com/Kalybus/ark-sdk-golang/pkg/profiles"
	"golang.org/x/term"
	"os"
	"pssh/config"
	"time"
)

func GetProfileName() string {
	profile := config.GetString("ark_profile")
	if profile == "" {
		profile = profiles.DeduceProfileName("")
	}
	return profile
}

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
