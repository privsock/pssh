package core

import (
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	ssomodels "github.com/Kalybus/ark-sdk-golang/pkg/models/services/pcloud/sshkeys"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/pcloud/sshkeys"
	"github.com/spf13/cobra"
	"os"
	"pssh/config"
	"pssh/ssh_client"
)

// GeneratePSMPMFAKey generates a short-lived MFA-enabled SSH key for authentication using PSMP service.
// Returns the SSH key as a string.
func (pssh *PSSH) GeneratePSMPMFAKey() string {
	profileAuthenticatorsMap := pssh.GetAuthenticators(true)
	// Build a slice of authenticators for PCloudSSHKeysService
	var authenticators []auth.ArkAuth
	for _, a := range profileAuthenticatorsMap {
		authenticators = append(authenticators, a)
	}
	ssoService, err := sshkeys.NewArkPCloudSSHKeysService(authenticators...)
	if err != nil {
		cobra.CheckErr(err)
		os.Exit(1)
	}
	key, err := ssoService.SSHKey(
		&ssomodels.ArkPCloudGetSSHKey{
			Format: "PEM",
		})
	return key
}

// ConnectWithPSMP establishes a secure SSH connection using psmp configuration parameters.
// Returns an error if authentication fails or if required parameters are missing.
func (pssh *PSSH) ConnectWithPSMP() error {
	cmdArgs := []string{"-o", "IdentityFile=none"}
	username, err := pssh.GetUsername()
	if err != nil {
		pssh.logger.Error("Missing username")
		return err
	}
	if len(pssh.Args) == 0 {
		pssh.logger.Error("Missing [user@]hostname")
		return errors.New("missing [user@]hostname")
	}
	content := pssh.Args[0]
	host := config.GetString("psmp_host")
	port := config.GetString("psmp_port")
	if port != "22" {
		cmdArgs = append(cmdArgs, "-p", port)
	}

	// VTL: <username>@<login_suffix>@<target_user>#account_domain@<target>[:target_port]@<PSMP gateway>
	connString := fmt.Sprintf("%s@%s@%s", username, content, host)
	cmdArgs = append(cmdArgs, connString)
	pssh.logger.Info("Connection string: %s", connString)
	err = ssh_client.SSH(cmdArgs)
	if err != nil {
		return err
	}
	return nil
}
