package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	backgroundSessionStateFileName = ".go-aws-saml.background.json"
	backgroundSessionLogFileName   = ".go-aws-saml.background.log"
	backgroundAttachPollInterval   = time.Second
)

type backgroundSession struct {
	PID     int    `json:"pid"`
	LogPath string `json:"log_path"`
}

var backgroundSessionLogWriter io.Writer

func runManagedBackgroundSession(stdin io.Reader, stdout io.Writer, configPath string, config *Config) error {
	sessionPath, session, err := prepareBackgroundSession()
	if err != nil {
		return err
	}
	defer cleanupBackgroundSession(sessionPath)

	logFile, err := os.OpenFile(session.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open background log %q: %w", session.LogPath, err)
	}
	defer logFile.Close()

	previousLogWriter := backgroundSessionLogWriter
	backgroundSessionLogWriter = logFile
	defer func() {
		backgroundSessionLogWriter = previousLogWriter
	}()

	backgroundSessionLogf("background refresh loop started (pid %d)", session.PID)
	err = runRefreshLoop(stdin, stdout, configPath, config, false, false)
	if err != nil {
		backgroundSessionLogf("background refresh loop stopped with error: %v", err)
		return err
	}

	backgroundSessionLogf("background refresh loop stopped")
	return nil
}

func reattachBackgroundSession(stdout io.Writer) (bool, error) {
	session, err := loadBackgroundSession()
	if err != nil {
		return false, err
	}
	if session == nil {
		return false, nil
	}

	if err := attachToBackgroundSession(stdout, *session); err != nil {
		return false, err
	}
	return true, nil
}

func prepareBackgroundSession() (string, backgroundSession, error) {
	sessionPath, logPath, err := backgroundSessionPaths()
	if err != nil {
		return "", backgroundSession{}, err
	}

	session := backgroundSession{
		PID:     os.Getpid(),
		LogPath: logPath,
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return "", backgroundSession{}, fmt.Errorf("serialize background session: %w", err)
	}

	if err := os.WriteFile(sessionPath, sessionBytes, 0600); err != nil {
		return "", backgroundSession{}, fmt.Errorf("write background session %q: %w", sessionPath, err)
	}

	return sessionPath, session, nil
}

func cleanupBackgroundSession(sessionPath string) {
	if err := os.Remove(sessionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		backgroundSessionLogf("failed to remove background session %s: %v", sessionPath, err)
	}
}

func backgroundSessionPaths() (string, string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("get user home directory: %w", err)
	}

	return filepath.Join(userHomeDir, backgroundSessionStateFileName), filepath.Join(userHomeDir, backgroundSessionLogFileName), nil
}

func loadBackgroundSession() (*backgroundSession, error) {
	sessionPath, _, err := backgroundSessionPaths()
	if err != nil {
		return nil, err
	}

	sessionBytes, err := os.ReadFile(sessionPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read background session %q: %w", sessionPath, err)
	}

	var session backgroundSession
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return nil, fmt.Errorf("parse background session %q: %w", sessionPath, err)
	}

	if session.PID <= 0 {
		return nil, fmt.Errorf("parse background session %q: missing pid", sessionPath)
	}
	if session.LogPath == "" {
		return nil, fmt.Errorf("parse background session %q: missing log path", sessionPath)
	}

	running, err := processRunning(session.PID)
	if err != nil {
		return nil, err
	}
	if running {
		return &session, nil
	}

	if err := os.Remove(sessionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale background session %q: %w", sessionPath, err)
	}
	return nil, nil
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

func attachToBackgroundSession(stdout io.Writer, session backgroundSession) error {
	logFile, err := os.OpenFile(session.LogPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("open background log %q: %w", session.LogPath, err)
	}
	defer logFile.Close()

	if _, err := fmt.Fprintf(stdout, "Reattached to background refresh loop (pid %d). Press Ctrl+C to detach.\n", session.PID); err != nil {
		return err
	}

	if _, err := io.Copy(stdout, logFile); err != nil {
		return fmt.Errorf("stream background log %q: %w", session.LogPath, err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case <-signals:
			_, _ = fmt.Fprintln(stdout, "\nDetached from background refresh loop.")
			return nil
		case <-time.After(backgroundAttachPollInterval):
			if _, err := io.Copy(stdout, logFile); err != nil {
				return fmt.Errorf("follow background log %q: %w", session.LogPath, err)
			}

			running, err := processRunning(session.PID)
			if err != nil {
				return err
			}
			if !running {
				_, _ = fmt.Fprintln(stdout, "Background refresh loop exited.")
				return nil
			}
		}
	}
}

func backgroundSessionLogf(format string, args ...any) {
	if backgroundSessionLogWriter == nil {
		return
	}

	_, _ = fmt.Fprintf(backgroundSessionLogWriter, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
}
