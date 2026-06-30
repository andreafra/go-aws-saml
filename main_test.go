package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestRefreshCredentialsWithSAMLPromptsAndSavesDefaultOnInitialRun(t *testing.T) {
	config := Config{
		Region:          "eu-west-1",
		RefreshInterval: 3500,
		Credentials:     CredentialsConfig{DefaultProfile: "dev"},
		Accounts: []Account{
			{Label: "dev"},
			{Label: "prod"},
		},
	}

	restore := stubMainDependencies()
	defer restore()

	authenticateWithBrowserFn = func(config Config) (string, error) {
		return "saml-response", nil
	}

	selectDefaultProfileFn = func(stdin io.Reader, stdout io.Writer, config *Config) (defaultProfileSelectionResult, error) {
		config.Credentials.DefaultProfile = "prod"
		return defaultProfileSelectionResult{changed: true}, nil
	}

	var savedConfigs []Config
	writeConfigFileFn = func(path string, config Config) error {
		savedConfigs = append(savedConfigs, config)
		return nil
	}

	assumeRolesCalled := false
	assumeRolesFn = func(region string, accounts []Account, samlResponse string) ([]RoleWithAccount, error) {
		assumeRolesCalled = true
		if region != "eu-west-1" {
			t.Fatalf("region = %q, want eu-west-1", region)
		}
		if samlResponse != "saml-response" {
			t.Fatalf("samlResponse = %q, want saml-response", samlResponse)
		}
		return nil, nil
	}

	writeCredentialsCalled := false
	writeRolesToAWSCredentialsFileFn = func(roles []RoleWithAccount, defaultProfile string) error {
		writeCredentialsCalled = true
		if defaultProfile != "prod" {
			t.Fatalf("defaultProfile = %q, want prod", defaultProfile)
		}
		return nil
	}

	var output bytes.Buffer
	backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(bytes.NewBuffer(nil), &output, "/tmp/config.yml", &config, true)
	if err != nil {
		t.Fatalf("refreshCredentialsWithSAML() error = %v", err)
	}
	if backgroundRequested {
		t.Fatal("refreshCredentialsWithSAML() backgroundRequested = true, want false")
	}
	if quitRequested {
		t.Fatal("refreshCredentialsWithSAML() quitRequested = true, want false")
	}
	if len(savedConfigs) != 1 {
		t.Fatalf("writeConfigFile() calls = %d, want 1", len(savedConfigs))
	}
	if savedConfigs[0].Credentials.DefaultProfile != "prod" {
		t.Fatalf("saved default profile = %q, want prod", savedConfigs[0].Credentials.DefaultProfile)
	}
	if !assumeRolesCalled {
		t.Fatal("assumeRoles() was not called")
	}
	if !writeCredentialsCalled {
		t.Fatal("writeRolesToAWSCredentialsFile() was not called")
	}
}

func TestRefreshCredentialsWithSAMLDoesNotPromptOnScheduledRefresh(t *testing.T) {
	config := Config{
		Region:          "eu-west-1",
		RefreshInterval: 3500,
		Credentials:     CredentialsConfig{DefaultProfile: "dev"},
		Accounts:        []Account{{Label: "dev"}},
	}

	restore := stubMainDependencies()
	defer restore()

	authenticateWithBrowserFn = func(config Config) (string, error) {
		return "saml-response", nil
	}

	selectDefaultProfileFn = func(stdin io.Reader, stdout io.Writer, config *Config) (defaultProfileSelectionResult, error) {
		t.Fatal("selectDefaultProfile() should not be called")
		return defaultProfileSelectionResult{}, nil
	}

	writeConfigFileFn = func(path string, config Config) error {
		t.Fatal("writeConfigFile() should not be called")
		return nil
	}

	assumeRolesFn = func(region string, accounts []Account, samlResponse string) ([]RoleWithAccount, error) {
		if region != "eu-west-1" {
			t.Fatalf("region = %q, want eu-west-1", region)
		}
		return nil, nil
	}

	writeRolesToAWSCredentialsFileFn = func(roles []RoleWithAccount, defaultProfile string) error {
		if defaultProfile != "dev" {
			t.Fatalf("defaultProfile = %q, want dev", defaultProfile)
		}
		return nil
	}

	backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(bytes.NewBuffer(nil), &bytes.Buffer{}, "/tmp/config.yml", &config, false)
	if err != nil {
		t.Fatalf("refreshCredentialsWithSAML() error = %v", err)
	}
	if backgroundRequested {
		t.Fatal("refreshCredentialsWithSAML() backgroundRequested = true, want false")
	}
	if quitRequested {
		t.Fatal("refreshCredentialsWithSAML() quitRequested = true, want false")
	}
}

func TestRefreshCredentialsWithSAMLRequestsBackgroundRun(t *testing.T) {
	config := Config{
		Region:          "eu-west-1",
		RefreshInterval: 3500,
		Credentials:     CredentialsConfig{DefaultProfile: "dev"},
		Accounts: []Account{
			{Label: "dev"},
			{Label: "sandbox"},
		},
	}

	restore := stubMainDependencies()
	defer restore()

	authenticateWithBrowserFn = func(config Config) (string, error) {
		return "saml-response", nil
	}

	selectDefaultProfileFn = func(stdin io.Reader, stdout io.Writer, config *Config) (defaultProfileSelectionResult, error) {
		config.Credentials.DefaultProfile = "sandbox"
		return defaultProfileSelectionResult{changed: true, background: true}, nil
	}

	var savedProfiles []string
	writeConfigFileFn = func(path string, config Config) error {
		savedProfiles = append(savedProfiles, config.Credentials.DefaultProfile)
		return nil
	}

	assumeRolesFn = func(region string, accounts []Account, samlResponse string) ([]RoleWithAccount, error) {
		if region != "eu-west-1" {
			t.Fatalf("region = %q, want eu-west-1", region)
		}
		return nil, nil
	}

	writeRolesToAWSCredentialsFileFn = func(roles []RoleWithAccount, defaultProfile string) error {
		if defaultProfile != "sandbox" {
			t.Fatalf("defaultProfile = %q, want sandbox", defaultProfile)
		}
		return nil
	}

	backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(bytes.NewBuffer(nil), &bytes.Buffer{}, "/tmp/config.yml", &config, true)
	if err != nil {
		t.Fatalf("refreshCredentialsWithSAML() error = %v", err)
	}
	if !backgroundRequested {
		t.Fatal("refreshCredentialsWithSAML() backgroundRequested = false, want true")
	}
	if quitRequested {
		t.Fatal("refreshCredentialsWithSAML() quitRequested = true, want false")
	}
	if len(savedProfiles) != 1 {
		t.Fatalf("writeConfigFile() calls = %d, want 1", len(savedProfiles))
	}
	if savedProfiles[0] != "sandbox" {
		t.Fatalf("savedProfiles = %v, want [sandbox]", savedProfiles)
	}
}

func TestRefreshCredentialsWithSAMLRequestsQuit(t *testing.T) {
	config := Config{
		Region:          "eu-west-1",
		RefreshInterval: 3500,
		Credentials:     CredentialsConfig{DefaultProfile: "dev"},
		Accounts: []Account{
			{Label: "dev"},
			{Label: "prod"},
		},
	}

	restore := stubMainDependencies()
	defer restore()

	authenticateWithBrowserFn = func(config Config) (string, error) {
		return "saml-response", nil
	}

	selectDefaultProfileFn = func(stdin io.Reader, stdout io.Writer, config *Config) (defaultProfileSelectionResult, error) {
		config.Credentials.DefaultProfile = "prod"
		return defaultProfileSelectionResult{changed: true, quit: true}, nil
	}

	writeConfigFileFn = func(path string, config Config) error {
		return nil
	}

	assumeRolesFn = func(region string, accounts []Account, samlResponse string) ([]RoleWithAccount, error) {
		if region != "eu-west-1" {
			t.Fatalf("region = %q, want eu-west-1", region)
		}
		return nil, nil
	}

	writeRolesToAWSCredentialsFileFn = func(roles []RoleWithAccount, defaultProfile string) error {
		return nil
	}

	backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(bytes.NewBuffer(nil), &bytes.Buffer{}, "/tmp/config.yml", &config, true)
	if err != nil {
		t.Fatalf("refreshCredentialsWithSAML() error = %v", err)
	}
	if backgroundRequested {
		t.Fatal("refreshCredentialsWithSAML() backgroundRequested = true, want false")
	}
	if !quitRequested {
		t.Fatal("refreshCredentialsWithSAML() quitRequested = false, want true")
	}
}

func TestRunSignURLWritesSignedURL(t *testing.T) {
	restore := stubMainDependencies()
	defer restore()

	loadConfigFileFn = func(path string, stdin io.Reader, stdout io.Writer) (Config, error) {
		return Config{
			Credentials: CredentialsConfig{DefaultProfile: "prod"},
		}, nil
	}

	signSelectedTenantURLFn = func(config Config, rawURL string, service string, region string, method string, expiresSeconds int) (string, error) {
		if rawURL != "https://cache.example.com/?Action=connect&User=test-user" {
			t.Fatalf("rawURL = %q", rawURL)
		}
		if service != "elasticache" {
			t.Fatalf("service = %q, want elasticache", service)
		}
		if method != "GET" {
			t.Fatalf("method = %q, want GET", method)
		}
		if expiresSeconds != defaultSignURLExpiresSeconds {
			t.Fatalf("expiresSeconds = %d, want %d", expiresSeconds, defaultSignURLExpiresSeconds)
		}
		return "signed-url", nil
	}

	var output bytes.Buffer
	err := run([]string{"--sign-url", "https://cache.example.com/?Action=connect&User=test-user"}, strings.NewReader(""), &output)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if output.String() != "signed-url\n" {
		t.Fatalf("output = %q, want signed-url\\n", output.String())
	}
}

func TestRunReattachesToExistingBackgroundSession(t *testing.T) {
	restore := stubMainDependencies()
	defer restore()

	loadConfigFileFn = func(path string, stdin io.Reader, stdout io.Writer) (Config, error) {
		return Config{
			Region:          "eu-west-1",
			RefreshInterval: 3500,
			Credentials:     CredentialsConfig{DefaultProfile: "prod"},
			Accounts:        []Account{{Label: "prod"}},
		}, nil
	}

	reattachBackgroundSessionFn = func(stdout io.Writer) (bool, error) {
		_, _ = io.WriteString(stdout, "attached\n")
		return true, nil
	}

	authenticateWithBrowserFn = func(config Config) (string, error) {
		t.Fatal("authenticateWithBrowser() should not be called when reattaching")
		return "", nil
	}

	var output bytes.Buffer
	if err := run(nil, strings.NewReader(""), &output); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if output.String() != "attached\n" {
		t.Fatalf("output = %q, want attached\\n", output.String())
	}
}

func TestRunBackgroundModeUsesManagedSession(t *testing.T) {
	restore := stubMainDependencies()
	defer restore()

	loadConfigFileFn = func(path string, stdin io.Reader, stdout io.Writer) (Config, error) {
		return Config{
			Region:          "eu-west-1",
			RefreshInterval: 3500,
			Credentials:     CredentialsConfig{DefaultProfile: "prod"},
			Accounts:        []Account{{Label: "prod"}},
		}, nil
	}

	managedSessionCalled := false
	runManagedBackgroundSessionFn = func(stdin io.Reader, stdout io.Writer, configPath string, config *Config) error {
		managedSessionCalled = true
		return nil
	}

	reattachBackgroundSessionFn = func(stdout io.Writer) (bool, error) {
		t.Fatal("reattachBackgroundSession() should not be called in --background-run mode")
		return false, nil
	}

	if err := run([]string{"--background-run"}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !managedSessionCalled {
		t.Fatal("runManagedBackgroundSession() was not called")
	}
}

func stubMainDependencies() func() {
	originalLoadConfigFileFn := loadConfigFileFn
	originalWriteConfigFileFn := writeConfigFileFn
	originalSelectDefaultProfileFn := selectDefaultProfileFn
	originalAuthenticateWithBrowserFn := authenticateWithBrowserFn
	originalAssumeRolesFn := assumeRolesFn
	originalWriteRolesToAWSCredentialsFileFn := writeRolesToAWSCredentialsFileFn
	originalStartBackgroundProcessFn := startBackgroundProcessFn
	originalReattachBackgroundSessionFn := reattachBackgroundSessionFn
	originalRunManagedBackgroundSessionFn := runManagedBackgroundSessionFn
	originalSignSelectedTenantURLFn := signSelectedTenantURLFn
	originalBuildIAMAuthTokenFn := buildIAMAuthTokenFn

	return func() {
		loadConfigFileFn = originalLoadConfigFileFn
		writeConfigFileFn = originalWriteConfigFileFn
		selectDefaultProfileFn = originalSelectDefaultProfileFn
		authenticateWithBrowserFn = originalAuthenticateWithBrowserFn
		assumeRolesFn = originalAssumeRolesFn
		writeRolesToAWSCredentialsFileFn = originalWriteRolesToAWSCredentialsFileFn
		startBackgroundProcessFn = originalStartBackgroundProcessFn
		reattachBackgroundSessionFn = originalReattachBackgroundSessionFn
		runManagedBackgroundSessionFn = originalRunManagedBackgroundSessionFn
		signSelectedTenantURLFn = originalSignSelectedTenantURLFn
		buildIAMAuthTokenFn = originalBuildIAMAuthTokenFn
	}
}
