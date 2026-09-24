//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func backgroundSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func releaseBackgroundProcess(process *os.Process) error {
	if err := process.Release(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func processRunning(pid int) (bool, error) {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, fmt.Errorf("check background session pid %d: %w", pid, err)
}

func backgroundDetachSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func enableRawTerminal(stdin io.Reader) (func(), error) {
	file, ok := stdin.(*os.File)
	if !ok {
		return nil, nil
	}

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat terminal: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return nil, nil
	}

	fd := int(file.Fd())
	state, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}

	rawState := *state
	rawState.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	rawState.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	rawState.Cflag &^= unix.CSIZE | unix.PARENB
	rawState.Cflag |= unix.CS8
	rawState.Cc[unix.VMIN] = 1
	rawState.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &rawState); err != nil {
		return nil, fmt.Errorf("set terminal raw mode: %w", err)
	}

	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TIOCSETA, state)
	}, nil
}
