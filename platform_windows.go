//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func backgroundSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func releaseBackgroundProcess(process *os.Process) error {
	return process.Release()
}

func processRunning(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		_ = windows.CloseHandle(handle)
		return true, nil
	}
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true, nil
	}
	return false, fmt.Errorf("check background session pid %d: %w", pid, err)
}

func backgroundDetachSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
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

	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}

	rawMode := rawConsoleMode(mode)
	if err := windows.SetConsoleMode(handle, rawMode); err != nil {
		return nil, fmt.Errorf("set terminal raw mode: %w", err)
	}

	return func() {
		_ = windows.SetConsoleMode(handle, mode)
	}, nil
}

func rawConsoleMode(mode uint32) uint32 {
	mode &^= windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	return mode
}
