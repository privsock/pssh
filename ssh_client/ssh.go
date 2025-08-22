package ssh_client

import (
	"fmt"
	"os"
	"os/exec"
	"pssh/ssh_agent"
	"runtime"
	"strings"
)

// SSH Connects using the system ssh client
func SSH(cmdArgs []string) error {
	sysArgs := []string{"ssh"}
	sysArgs = append(sysArgs, cmdArgs...)
	sshPath, err := DetectSSHPath()
	if err != nil {
		return fmt.Errorf("failed to detect ssh path: %s", err)
	}
	environ := AddOrUpdateEnv(os.Environ(), "SSH_AUTH_SOCK", ssh_agent.SocketPath())
	err = Exec(sshPath, sysArgs, environ)
	if err != nil {
		return err
	}
	return nil
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
