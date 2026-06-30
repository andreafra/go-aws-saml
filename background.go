package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func startBackgroundProcess() error {
	session, err := loadBackgroundSession()
	if err != nil {
		return err
	}
	if session != nil {
		return nil
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	process, err := os.StartProcess(executablePath, []string{executablePath, "--background-run"}, &os.ProcAttr{
		Dir:   "",
		Env:   os.Environ(),
		Files: []*os.File{devNull, devNull, devNull},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("start background refresh process: %w", err)
	}

	if err := process.Release(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("release background refresh process: %w", err)
	}

	return nil
}
