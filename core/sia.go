package core

import (
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	ssomodels "github.com/Kalybus/ark-sdk-golang/pkg/models/services/sia/sso"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/sia/sso"
	"github.com/spf13/cobra"
	"os"
	"pssh/config"
	"pssh/ssh_client"
)

// GenerateSIAMFAKey generates a short-lived MFA-enabled SSH key for authentication using SIA service.
// Returns the SSH key as a string or an error if key generation fails.
func (pssh *PSSH) GenerateSIAMFAKey() (string, error) {
	profileAuthenticatorsMap := pssh.GetAuthenticators(true)
	// Build a slice of authenticators for SIASSOService
	var authenticators []auth.ArkAuth
	for _, a := range profileAuthenticatorsMap {
		authenticators = append(authenticators, a)
	}
	ssoService, err := sso.NewArkSIASSOService(authenticators...)
	if err != nil {
		cobra.CheckErr(err)
		os.Exit(1)
	}
	// Generate a short-lived password for SSH
	path, err := os.MkdirTemp("", "pssh-mfa-*")
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			pssh.logger.Error("Failed to remove temporary directory: %s", err)
			args.PrintFailure(fmt.Sprintf("Failed to remove temporary directory: %s", err))
		}
	}(path)
	if err != nil {
		pssh.logger.Error("Failed to create temporary directory: %s", err)
		return "", fmt.Errorf("failed to create temporary directory: %s", err)
	}
	sshKeyPath, err := ssoService.ShortLivedSSHKey(
		&ssomodels.ArkSIASSOGetSSHKey{
			Folder: path,
		})
	key, err := os.ReadFile(sshKeyPath)
	if err != nil {
		pssh.logger.Error("Failed to read mfa key file %s", err)
		return "", fmt.Errorf("failed to read mfa key file: %s", err)
	}
	return string(key), nil
}

// ConnectWithSIA establishes a secure SSH connection using sia configuration parameters.
// Returns an error if authentication fails or if required parameters are missing.
func (pssh *PSSH) ConnectWithSIA() error {
	cmdArgs := []string{"-o", "IdentityFile=none"}
	username, err := pssh.GetUsername()
	if err != nil {
		pssh.logger.Error("Missing username")
		return err
	}
	subdomain, err := pssh.GetSubdomain()
	if err != nil {
		pssh.logger.Error("Missing subdomain")
		return err
	}
	if len(pssh.Args) == 0 {
		pssh.logger.Error("Missing [user@]hostname")
		return errors.New("missing [user@]hostname")
	}
	content := pssh.Args[0]
	host := fmt.Sprintf("%s.ssh.cyberark.cloud", subdomain)
	network, err := pssh.GetSIANetworkParam()
	if err != nil {
		pssh.logger.Error("Unable to fetch SIA network: %v", err)
		return err
	}
	// Adding the network delimiter if network is defined
	if network != "" {
		network = fmt.Sprintf("#%s", network)
	}
	// ZSP: <username>@<login_suffix>#<subdomain>@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	// VTL: <username>@<login_suffix>#<subdomain>@<target_user>#account_domain@<target>[:target_port]#<NetworkName>@<SSH gateway> <inline_commands>
	connString := fmt.Sprintf("%s#%s@%s%s@%s", username, subdomain, content, network, host)
	cmdArgs = append(cmdArgs, connString)
	pssh.logger.Info("Connection string: %s", connString)
	err = ssh_client.SSH(cmdArgs)
	if err != nil {
		return err
	}
	return nil
}

func (pssh *PSSH) GetSIANetworkParam() (string, error) {
	network, err := pssh.cmd.Flags().GetString("network")
	if err != nil {
		pssh.logger.Error("Failed to get network parameter")
		return "", errors.New("failed to get network parameter")
	}
	if network == "" {
		network = config.GetString("sia_network")
	}
	if network == "" {
		pssh.logger.Debug("No SIA network found")
		return "", nil
	}
	return network, nil
}
