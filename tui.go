package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type defaultProfileSelectionResult struct {
	changed    bool
	background bool
	quit       bool
}

type defaultProfileMenuState struct {
	signedToken   string
	signError     string
	signedProfile string
	signedTarget  string
}

func selectDefaultProfile(stdin io.Reader, stdout io.Writer, config *Config) (defaultProfileSelectionResult, error) {
	if len(config.Accounts) == 0 {
		return defaultProfileSelectionResult{}, fmt.Errorf("cannot select a default profile because no accounts are configured")
	}

	reader := bufio.NewReader(stdin)
	selectedIndex := defaultProfileSelectionIndex(*config)
	changed := false
	menuState := defaultProfileMenuState{}

	restoreTerminal, err := enableRawTerminal(stdin)
	if err != nil {
		return defaultProfileSelectionResult{}, err
	}
	if restoreTerminal != nil {
		defer restoreTerminal()
	}

	for {
		renderDefaultProfileMenu(stdout, *config, selectedIndex, menuState)

		key, err := readMenuKey(reader)
		if err != nil {
			if err == io.EOF {
				_, _ = fmt.Fprintln(stdout)
				return defaultProfileSelectionResult{changed: changed}, nil
			}
			return defaultProfileSelectionResult{}, fmt.Errorf("read default profile selection: %w", err)
		}

		switch key {
		case menuKeyUp:
			if selectedIndex > 0 {
				selectedIndex--
			}
		case menuKeyDown:
			if selectedIndex < len(config.Accounts)-1 {
				selectedIndex++
			}
		case menuKeySelect:
			selectedProfile := config.Accounts[selectedIndex].Label
			if selectedProfile != config.Credentials.DefaultProfile {
				config.Credentials.DefaultProfile = selectedProfile
				changed = true
			}
			menuState.signError = ""
		case menuKeySignURL:
			if len(config.IAMAuthTokenRequests) == 0 {
				menuState.signedToken = ""
				menuState.signedProfile = ""
				menuState.signedTarget = ""
				menuState.signError = fmt.Sprintf("no iam-auth-token-requests configured in %s", configFileName)
				continue
			}

			requestConfig, ok, err := selectIAMAuthTokenRequest(reader, stdout, *config)
			if err != nil {
				return defaultProfileSelectionResult{}, err
			}
			if !ok {
				continue
			}

			selectedProfile := config.Accounts[selectedIndex].Label
			token, err := buildIAMAuthTokenFn(*config, selectedProfile, requestConfig)
			if err != nil {
				menuState.signedToken = ""
				menuState.signedProfile = ""
				menuState.signedTarget = ""
				menuState.signError = err.Error()
				continue
			}
			menuState.signedToken = token
			menuState.signedProfile = selectedProfile
			menuState.signedTarget = displayIAMAuthTokenRequestName(requestConfig)
			menuState.signError = ""
		case menuKeyQuit:
			_, _ = fmt.Fprintln(stdout)
			return defaultProfileSelectionResult{changed: changed, quit: true}, nil
		case menuKeyBackground:
			selectedProfile := config.Accounts[selectedIndex].Label
			if selectedProfile != config.Credentials.DefaultProfile {
				config.Credentials.DefaultProfile = selectedProfile
				changed = true
			}
			_, _ = fmt.Fprintln(stdout)
			return defaultProfileSelectionResult{changed: changed, background: true}, nil
		}
	}
}

func renderDefaultProfileMenu(stdout io.Writer, config Config, selectedIndex int, menuState defaultProfileMenuState) {
	_, _ = fmt.Fprint(stdout, "\x1b[H\x1b[2J")

	_, _ = fmt.Fprintln(stdout, "go-aws-saml")
	_, _ = fmt.Fprintln(stdout, "Select the tenant to use as the AWS default profile.")
	_, _ = fmt.Fprintln(stdout)

	if config.Credentials.DefaultProfile == "" {
		_, _ = fmt.Fprintln(stdout, "Current default profile: none")
	} else {
		_, _ = fmt.Fprintf(stdout, "Current default profile: %s\n", config.Credentials.DefaultProfile)
	}

	_, _ = fmt.Fprintln(stdout)
	labelWidth, accountWidth, roleWidth := defaultProfileColumnWidths(config)
	_, _ = fmt.Fprintf(
		stdout,
		"  %-*s  %-*s  %-*s\n",
		labelWidth,
		"Tenant",
		accountWidth,
		"Account",
		roleWidth,
		"Role",
	)
	_, _ = fmt.Fprintf(
		stdout,
		"  %s  %s  %s\n",
		strings.Repeat("-", labelWidth),
		strings.Repeat("-", accountWidth),
		strings.Repeat("-", roleWidth),
	)

	for i, account := range config.Accounts {
		cursorMarker := " "
		if i == selectedIndex {
			cursorMarker = ">"
		}

		currentMarker := ""
		if account.Label == config.Credentials.DefaultProfile {
			currentMarker = " *"
		}

		_, _ = fmt.Fprintf(
			stdout,
			"%s %-*s  %-*s  %-*s\n",
			cursorMarker,
			labelWidth,
			account.Label+currentMarker,
			accountWidth,
			account.AccountNumber,
			roleWidth,
			account.IAMRole,
		)
	}
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, "Use Up/Down to choose a tenant. Press Space or Enter to set it, u to build IAM auth token, q to quit, or d to run in background.")
	if menuState.signError != "" {
		_, _ = fmt.Fprintln(stdout)
		_, _ = fmt.Fprintf(stdout, "IAM auth token error: %s\n", menuState.signError)
	}
	if menuState.signedToken != "" {
		_, _ = fmt.Fprintln(stdout)
		_, _ = fmt.Fprintf(stdout, "IAM auth token for %s (%s):\n", menuState.signedProfile, menuState.signedTarget)
		_, _ = fmt.Fprintln(stdout, menuState.signedToken)
	}
}

func selectIAMAuthTokenRequest(reader *bufio.Reader, stdout io.Writer, config Config) (IAMAuthTokenConfig, bool, error) {
	selectedIndex := 0

	for {
		renderIAMAuthTokenRequestMenu(stdout, config, selectedIndex)

		key, err := readMenuKey(reader)
		if err != nil {
			if err == io.EOF {
				_, _ = fmt.Fprintln(stdout)
				return IAMAuthTokenConfig{}, false, nil
			}
			return IAMAuthTokenConfig{}, false, fmt.Errorf("read IAM auth token request selection: %w", err)
		}

		switch key {
		case menuKeyUp:
			if selectedIndex > 0 {
				selectedIndex--
			}
		case menuKeyDown:
			if selectedIndex < len(config.IAMAuthTokenRequests)-1 {
				selectedIndex++
			}
		case menuKeySelect:
			return config.IAMAuthTokenRequests[selectedIndex], true, nil
		case menuKeyQuit:
			return IAMAuthTokenConfig{}, false, nil
		}
	}
}

func renderIAMAuthTokenRequestMenu(stdout io.Writer, config Config, selectedIndex int) {
	_, _ = fmt.Fprint(stdout, "\x1b[H\x1b[2J")
	_, _ = fmt.Fprintln(stdout, "go-aws-saml")
	_, _ = fmt.Fprintln(stdout, "Select the IAM auth token request.")
	_, _ = fmt.Fprintln(stdout)

	nameWidth, cacheWidth, userWidth := iamAuthTokenRequestColumnWidths(config.IAMAuthTokenRequests)
	_, _ = fmt.Fprintf(stdout, "  %-*s  %-*s  %-*s\n", nameWidth, "Name", cacheWidth, "Cache", userWidth, "User")
	_, _ = fmt.Fprintf(stdout, "  %s  %s  %s\n",
		strings.Repeat("-", nameWidth),
		strings.Repeat("-", cacheWidth),
		strings.Repeat("-", userWidth),
	)

	for i, request := range config.IAMAuthTokenRequests {
		cursorMarker := " "
		if i == selectedIndex {
			cursorMarker = ">"
		}

		_, _ = fmt.Fprintf(
			stdout,
			"%s %-*s  %-*s  %-*s\n",
			cursorMarker,
			nameWidth,
			displayIAMAuthTokenRequestName(request),
			cacheWidth,
			request.CacheName,
			userWidth,
			request.UserID,
		)
	}

	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, "Use Up/Down to choose a request. Press Space or Enter to build the token, or q to go back.")
}

func defaultProfileColumnWidths(config Config) (int, int, int) {
	labelWidth := len("Tenant")
	accountWidth := len("Account")
	roleWidth := len("Role")

	for _, account := range config.Accounts {
		labelWidth = max(labelWidth, len(account.Label)+defaultMarkerWidth(config, account))
		accountWidth = max(accountWidth, len(account.AccountNumber))
		roleWidth = max(roleWidth, len(account.IAMRole))
	}

	return labelWidth, accountWidth, roleWidth
}

func defaultMarkerWidth(config Config, account Account) int {
	if account.Label == config.Credentials.DefaultProfile {
		return 2
	}

	return 0
}

func max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func iamAuthTokenRequestColumnWidths(requests []IAMAuthTokenConfig) (int, int, int) {
	nameWidth := len("Name")
	cacheWidth := len("Cache")
	userWidth := len("User")

	for _, request := range requests {
		nameWidth = max(nameWidth, len(displayIAMAuthTokenRequestName(request)))
		cacheWidth = max(cacheWidth, len(request.CacheName))
		userWidth = max(userWidth, len(request.UserID))
	}

	return nameWidth, cacheWidth, userWidth
}

func displayIAMAuthTokenRequestName(request IAMAuthTokenConfig) string {
	if strings.TrimSpace(request.Name) != "" {
		return request.Name
	}

	return request.CacheName
}

type menuKey int

const (
	menuKeyUnknown menuKey = iota
	menuKeyUp
	menuKeyDown
	menuKeySelect
	menuKeySignURL
	menuKeyQuit
	menuKeyBackground
)

func defaultProfileSelectionIndex(config Config) int {
	for i, account := range config.Accounts {
		if account.Label == config.Credentials.DefaultProfile {
			return i
		}
	}

	return 0
}

func readMenuKey(reader *bufio.Reader) (menuKey, error) {
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return menuKeyUnknown, err
		}

		switch b {
		case '\r', '\n', ' ':
			return menuKeySelect, nil
		case 'u':
			return menuKeySignURL, nil
		case 3, 'q':
			return menuKeyQuit, nil
		case 'd':
			return menuKeyBackground, nil
		case 27:
			next, err := reader.ReadByte()
			if err != nil {
				return menuKeyUnknown, err
			}
			if next != '[' {
				continue
			}

			arrow, err := reader.ReadByte()
			if err != nil {
				return menuKeyUnknown, err
			}

			switch arrow {
			case 'A':
				return menuKeyUp, nil
			case 'B':
				return menuKeyDown, nil
			}
		}
	}
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
	state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
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

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &rawState); err != nil {
		return nil, fmt.Errorf("set terminal raw mode: %w", err)
	}

	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, state)
	}, nil
}
