package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRoundTripIncludesDefaultProfile(t *testing.T) {
	path := t.TempDir() + "/config.yml"
	want := Config{
		Region: "eu-west-1",
		Credentials: CredentialsConfig{
			DefaultProfile: "prod",
			Username:       "user",
			Password:       "pass",
			TOTP:           "totp",
		},
		Accounts: []Account{
			{Label: "prod", Env: "production", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
		RefreshInterval: 3500,
	}

	if err := writeConfigFile(path, want); err != nil {
		t.Fatalf("writeConfigFile() error = %v", err)
	}

	got, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("readConfigFile() error = %v", err)
	}

	if got.Credentials.DefaultProfile != want.Credentials.DefaultProfile {
		t.Fatalf("DefaultProfile = %q, want %q", got.Credentials.DefaultProfile, want.Credentials.DefaultProfile)
	}
	if got.Region != want.Region {
		t.Fatalf("Region = %q, want %q", got.Region, want.Region)
	}
}

func TestValidateRuntimeConfigRejectsUnknownDefaultProfile(t *testing.T) {
	config := validRuntimeConfig()
	config.Credentials.DefaultProfile = "missing"

	err := validateRuntimeConfig(config)
	if err == nil {
		t.Fatal("validateRuntimeConfig() error = nil, want error")
	}
}

func TestValidateRuntimeConfigRejectsDuplicateAccountLabels(t *testing.T) {
	config := validRuntimeConfig()
	config.Accounts = append(config.Accounts, config.Accounts[0])

	err := validateRuntimeConfig(config)
	if err == nil {
		t.Fatal("validateRuntimeConfig() error = nil, want error")
	}
}

func TestLoadConfigFileCreatesDefaultAndOpensEditorWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	var output bytes.Buffer

	originalRunEditor := runEditor
	t.Cleanup(func() {
		runEditor = originalRunEditor
	})

	editorCalled := false
	runEditor = func(editor string, path string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
		editorCalled = true
		if editor != "test-editor" {
			t.Fatalf("editor = %q, want test-editor", editor)
		}
		if _, err := stdout.Write([]byte("editor opened\n")); err != nil {
			t.Fatalf("stdout.Write() error = %v", err)
		}
		return nil
	}

	t.Setenv("VISUAL", "test-editor")
	config, err := loadConfigFile(path, strings.NewReader(""), &output)
	if err != nil {
		t.Fatalf("loadConfigFile() error = %v", err)
	}
	if !editorCalled {
		t.Fatal("runEditor() was not called")
	}
	if config.Credentials.DefaultProfile != "sandbox" {
		t.Fatalf("DefaultProfile = %q, want sandbox", config.Credentials.DefaultProfile)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if !strings.Contains(output.String(), "Created "+path+" with default values.") {
		t.Fatalf("output = %q, want creation message", output.String())
	}
}

func TestResolveEditorPrefersVisualOverEditor(t *testing.T) {
	t.Setenv("VISUAL", "visual-editor")
	t.Setenv("EDITOR", "fallback-editor")

	editor, err := resolveEditor()
	if err != nil {
		t.Fatalf("resolveEditor() error = %v", err)
	}
	if editor != "visual-editor" {
		t.Fatalf("editor = %q, want visual-editor", editor)
	}
}

func TestReadConfigFileDefaultsHeadlessToTrueWhenUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	configYAML := `
refresh-in-seconds: 3500
region: eu-west-1
credentials:
  default: sandbox
  username: user
  password: pass
  totp: secret
accounts:
  - label: sandbox
    iam-role: Role
    saml-provider: Provider
    env: sandbox
    account: "123456789012"
browser:
  starting-url: https://example.com/saml/login
  executable-path: /mnt/c/Program Files/Google/Chrome/Application/chrome.exe
  debug: true
  login:
    wait-for-selector: "#username"
    username-selector: "#username"
    password-selector: "#password"
    submit-selector: "#submit-login"
  totp:
    wait-for-selector: //*[@id="otp"]
    totp-selector: //*[@id="otp"]
    submit-selector: "#submit-dissms"
`

	if err := os.WriteFile(path, []byte(configYAML), 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	config, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("readConfigFile() error = %v", err)
	}
	if !config.Browser.headlessEnabled() {
		t.Fatal("headlessEnabled() = false, want true when unset")
	}
	if config.Region != "eu-west-1" {
		t.Fatalf("Region = %q, want eu-west-1", config.Region)
	}
	if !config.Browser.Debug {
		t.Fatal("Debug = false, want true")
	}
	if config.Browser.ExecutablePath != "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe" {
		t.Fatalf("ExecutablePath = %q", config.Browser.ExecutablePath)
	}
}

func TestBrowserHeadlessEnabledHonorsExplicitFalse(t *testing.T) {
	config := BrowserConfig{Headless: boolPtr(false)}

	if config.headlessEnabled() {
		t.Fatal("headlessEnabled() = true, want false")
	}
}

func validRuntimeConfig() Config {
	return Config{
		Region:      "eu-west-1",
		Credentials: CredentialsConfig{DefaultProfile: "prod"},
		Accounts: []Account{
			{Label: "prod", Env: "production", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
		RefreshInterval: 3500,
	}
}
