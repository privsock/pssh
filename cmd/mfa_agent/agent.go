package mfa_agent

import (
	"context"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/args"
	"github.com/spf13/cobra"
	"os"
	sshagentclient "pssh/ssh_agent/client"
	sshagentserver "pssh/ssh_agent/server"
	"sync"
	"time"
)

var MfaAgentCmd = &cobra.Command{
	Use:   "mfa-agent",
	Short: "Start MFA Agent",
	Long:  `Start MFA Agent`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, execArgs []string) {
		if sshagentserver.IsRunning() {
			args.PrintFailure("MFA agent is already running")
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		go MonitoringLoop(ctx)
		sshagentserver.Start()
		defer cancel()
	},
}

func resetTimer(timer *time.Timer, timerMutex *sync.Mutex) *time.Timer {
	timerMutex.Lock()
	defer timerMutex.Unlock()

	if timer != nil {
		timer.Stop()
	}
	timer = time.AfterFunc(1*time.Hour, func() {
		args.PrintNormal("No key loaded for 1 hour. Killing agent...")
		os.Exit(0)
	})

	return timer
}

func MonitoringLoop(ctx context.Context) {
	var timer *time.Timer
	timerMutex := &sync.Mutex{}
	wasKey := true
	for {
		select {
		case <-ctx.Done():
			return
		default:
			isKey := isKeyPresent()
			if isKey && !wasKey {
				args.PrintSuccess("Key loaded, agent will not exit...")
				timer = resetTimer(timer, timerMutex)
				timer.Stop()
				wasKey = true
			} else if !isKey && wasKey {
				args.PrintFailure("No key loaded, agent will exit in 1 hour...")
				timer = resetTimer(timer, timerMutex)
				wasKey = false
			}
			time.Sleep(10 * time.Second) // poll interval
		}
	}
}

func isKeyPresent() bool {
	keys, err := sshagentclient.GetKeys()
	if err == nil && len(keys) > 0 {
		return true
	}
	return false
}
