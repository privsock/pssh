//go:build !windows

package cmd

import "syscall"

func ProgramExec(program string, args []string, environ []string) error {
	err := syscall.Exec(program, args, environ)
	// Except for any error, program should stop here
	if err != nil {
		return err
	}
	return nil
}
