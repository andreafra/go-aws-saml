package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

const configFileName = ".go-aws-saml.yml"

type Config struct {
	Region               string               `yaml:"region,omitempty"`
	Credentials          CredentialsConfig    `yaml:"credentials"`
	Accounts             []Account            `yaml:"accounts"`
	Browser              BrowserConfig        `yaml:"browser"`
	IAMAuthTokenRequests []IAMAuthTokenConfig `yaml:"iam-auth-token-requests,omitempty"`
	RefreshInterval      int                  `yaml:"refresh-in-seconds"`
}

type CredentialsConfig struct {
	DefaultProfile string `yaml:"default,omitempty"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	TOTP           string `yaml:"totp"`
}

type Account struct {
	Label         string `yaml:"label"`
	IAMRole       string `yaml:"iam-role"`
	SAMLProvider  string `yaml:"saml-provider"`
	Env           string `yaml:"env"`
	AccountNumber string `yaml:"account"`
}

type BrowserConfig struct {
	StartingURL    string      `yaml:"starting-url"`
	ExecutablePath string      `yaml:"executable-path,omitempty"`
	Headless       *bool       `yaml:"headless,omitempty"`
	Debug          bool        `yaml:"debug,omitempty"`
	Login          LoginConfig `yaml:"login"`
	TOTP           TOTPConfig  `yaml:"totp"`
}

type LoginConfig struct {
	WaitForSelector  string `yaml:"wait-for-selector"`
	UsernameSelector string `yaml:"username-selector"`
	PasswordSelector string `yaml:"password-selector"`
	SubmitSelector   string `yaml:"submit-selector"`
}

type TOTPConfig struct {
	WaitForSelector string `yaml:"wait-for-selector"`
	TOTPSelector    string `yaml:"totp-selector"`
	SubmitSelector  string `yaml:"submit-selector"`
}

type IAMAuthTokenConfig struct {
	Name         string `yaml:"name,omitempty"`
	UserID       string `yaml:"user-id,omitempty"`
	CacheName    string `yaml:"cache-name,omitempty"`
	Region       string `yaml:"region,omitempty"`
	IsServerless bool   `yaml:"is-serverless,omitempty"`
}

func defaultConfigPath() (string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home directory: %w", err)
	}

	return filepath.Join(userHomeDir, configFileName), nil
}

func readConfigFile(path string) (Config, error) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	var config Config
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return Config{}, fmt.Errorf("parse config file %q: %w", path, err)
	}

	return config, nil
}

func loadConfigFile(path string, stdin io.Reader, stdout io.Writer) (Config, error) {
	config, err := readConfigFile(path)
	if err == nil {
		return config, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	config = defaultConfig()
	if err := writeConfigFile(path, config); err != nil {
		return Config{}, err
	}

	_, _ = fmt.Fprintf(stdout, "Created %s with default values.\n", path)
	if err := openConfigInEditor(path, stdin, stdout, os.Stderr); err != nil {
		return Config{}, err
	}

	return readConfigFile(path)
}

func writeConfigFile(path string, config Config) error {
	configBytes, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("serialize config file %q: %w", path, err)
	}

	if err := os.WriteFile(path, configBytes, 0600); err != nil {
		return fmt.Errorf("write config file %q: %w", path, err)
	}

	return nil
}

func defaultConfig() Config {
	return Config{
		Region:          "eu-west-1",
		RefreshInterval: 3500,
		Credentials: CredentialsConfig{
			DefaultProfile: "sandbox",
			Username:       "your-username",
			Password:       "your-password",
			TOTP:           "JBSWY3DPEHPK3PXP",
		},
		Accounts: []Account{
			{
				Label:         "sandbox",
				IAMRole:       "YourRole",
				SAMLProvider:  "YourProvider",
				Env:           "sandbox",
				AccountNumber: "123456789012",
			},
		},
		Browser: BrowserConfig{
			StartingURL:    "https://example.com/saml/login",
			ExecutablePath: "",
			Headless:       boolPtr(true),
			Debug:          false,
			Login: LoginConfig{
				WaitForSelector:  "#username",
				UsernameSelector: "#username",
				PasswordSelector: "#password",
				SubmitSelector:   "#submit-login",
			},
			TOTP: TOTPConfig{
				WaitForSelector: `//*[@id="otp"]`,
				TOTPSelector:    `//*[@id="otp"]`,
				SubmitSelector:  "#submit-dissms",
			},
		},
		IAMAuthTokenRequests: []IAMAuthTokenConfig{
			{
				Name:         "redis-primary",
				UserID:       "iam-user",
				CacheName:    "cache-name",
				Region:       "eu-west-1",
				IsServerless: true,
			},
		},
	}
}

var runEditor = func(editor string, path string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	args := strings.Fields(editor)
	if len(args) == 0 {
		return fmt.Errorf("empty editor command")
	}

	cmd := exec.Command(args[0], append(args[1:], path)...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("open editor %q for %q: %w", editor, path, err)
	}

	return nil
}

func openConfigInEditor(path string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	editor, err := resolveEditor()
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "Opening %s in %s\n", path, editor)
	return runEditor(editor, path, stdin, stdout, stderr)
}

func resolveEditor() (string, error) {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value, nil
		}
	}

	for _, candidate := range []string{"editor", "nano", "vim", "vi"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no editor configured; set $VISUAL or $EDITOR")
}

func (c BrowserConfig) headlessEnabled() bool {
	return c.Headless == nil || *c.Headless
}

func boolPtr(value bool) *bool {
	return &value
}

func normalizedRegionValue(region string) string {
	return strings.TrimSpace(region)
}

func defaultRegionValue(config Config) string {
	return normalizedRegionValue(config.Region)
}

func validateRuntimeConfig(config Config) error {
	if config.RefreshInterval <= 0 {
		return fmt.Errorf("refresh-in-seconds must be greater than 0")
	}
	if len(config.Accounts) == 0 {
		return fmt.Errorf("at least one account must be configured")
	}

	labels := make(map[string]struct{}, len(config.Accounts))
	for _, account := range config.Accounts {
		label := strings.TrimSpace(account.Label)
		if label == "" {
			return fmt.Errorf("account label must not be empty")
		}
		if _, exists := labels[label]; exists {
			return fmt.Errorf("account label %q is configured more than once", label)
		}
		labels[label] = struct{}{}
	}

	defaultProfile := config.Credentials.DefaultProfile
	if defaultProfile == "" {
		return nil
	}

	if _, exists := labels[defaultProfile]; !exists {
		return fmt.Errorf("credentials.default %q does not match any configured account label", defaultProfile)
	}

	return nil
}
