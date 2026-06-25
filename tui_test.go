package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSelectDefaultProfileUpdatesConfigWithArrowDownAndEnter(t *testing.T) {
	config := Config{
		Credentials: CredentialsConfig{DefaultProfile: "dev"},
		Accounts: []Account{
			{Label: "dev", Env: "development", AccountNumber: "111111111111", IAMRole: "Developer"},
			{Label: "prod", Env: "production", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("\x1b[B\nq"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if !result.changed {
		t.Fatal("selectDefaultProfile() changed = false, want true")
	}
	if result.background {
		t.Fatal("selectDefaultProfile() background = true, want false")
	}
	if !result.quit {
		t.Fatal("selectDefaultProfile() quit = false, want true")
	}
	if config.Credentials.DefaultProfile != "prod" {
		t.Fatalf("DefaultProfile = %q, want prod", config.Credentials.DefaultProfile)
	}
}

func TestSelectDefaultProfileKeepsCurrentDefaultOnQuit(t *testing.T) {
	config := Config{
		Credentials: CredentialsConfig{DefaultProfile: "dev"},
		Accounts: []Account{
			{Label: "dev", Env: "development", AccountNumber: "111111111111", IAMRole: "Developer"},
		},
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("q"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if result.changed {
		t.Fatal("selectDefaultProfile() changed = true, want false")
	}
	if !result.quit {
		t.Fatal("selectDefaultProfile() quit = false, want true")
	}
	if config.Credentials.DefaultProfile != "dev" {
		t.Fatalf("DefaultProfile = %q, want dev", config.Credentials.DefaultProfile)
	}
}

func TestSelectDefaultProfileUpdatesConfigWithSpace(t *testing.T) {
	config := Config{
		Accounts: []Account{
			{Label: "dev", Env: "development", AccountNumber: "111111111111", IAMRole: "Developer"},
			{Label: "prod", Env: "production", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("\x1b[B q"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if !result.changed {
		t.Fatal("selectDefaultProfile() changed = false, want true")
	}
	if !result.quit {
		t.Fatal("selectDefaultProfile() quit = false, want true")
	}
	if config.Credentials.DefaultProfile != "prod" {
		t.Fatalf("DefaultProfile = %q, want prod", config.Credentials.DefaultProfile)
	}
}

func TestSelectDefaultProfileRequestsBackgroundRun(t *testing.T) {
	config := Config{
		Accounts: []Account{
			{Label: "dev", AccountNumber: "111111111111", IAMRole: "Developer"},
			{Label: "prod", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("\x1b[Bd"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if !result.changed {
		t.Fatal("selectDefaultProfile() changed = false, want true")
	}
	if !result.background {
		t.Fatal("selectDefaultProfile() background = false, want true")
	}
	if result.quit {
		t.Fatal("selectDefaultProfile() quit = true, want false")
	}
	if config.Credentials.DefaultProfile != "prod" {
		t.Fatalf("DefaultProfile = %q, want prod", config.Credentials.DefaultProfile)
	}
}

func TestSelectDefaultProfileBuildsIAMAuthTokenForHighlightedTenant(t *testing.T) {
	config := Config{
		Accounts: []Account{
			{Label: "dev", AccountNumber: "111111111111", IAMRole: "Developer"},
			{Label: "prod", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
		IAMAuthTokenRequests: []IAMAuthTokenConfig{
			{
				Name:         "primary",
				UserID:       "iam-user",
				CacheName:    "cache-name",
				Region:       "eu-west-1",
				IsServerless: true,
			},
			{
				Name:         "secondary",
				UserID:       "iam-user-2",
				CacheName:    "cache-name-2",
				Region:       "eu-west-1",
				IsServerless: false,
			},
		},
	}

	originalBuildIAMAuthTokenFn := buildIAMAuthTokenFn
	t.Cleanup(func() {
		buildIAMAuthTokenFn = originalBuildIAMAuthTokenFn
	})

	buildIAMAuthTokenFn = func(config Config, profile string, request IAMAuthTokenConfig) (string, error) {
		if profile != "prod" {
			t.Fatalf("profile = %q, want prod", profile)
		}
		if request.Name != "secondary" {
			t.Fatalf("request.Name = %q, want secondary", request.Name)
		}
		return "signed-token", nil
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("\x1b[Bu\x1b[B q"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if result.changed {
		t.Fatal("selectDefaultProfile() changed = true, want false")
	}
	if !result.quit {
		t.Fatal("selectDefaultProfile() quit = false, want true")
	}
	if !strings.Contains(output.String(), "IAM auth token for prod (secondary):\nsigned-token\n") {
		t.Fatalf("output = %q, want IAM auth token footer", output.String())
	}
}

func TestSelectDefaultProfileHandlesMissingIAMAuthTokenRequests(t *testing.T) {
	config := Config{
		Accounts: []Account{
			{Label: "prod", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
	}

	var output bytes.Buffer
	result, err := selectDefaultProfile(strings.NewReader("uq"), &output, &config)
	if err != nil {
		t.Fatalf("selectDefaultProfile() error = %v", err)
	}
	if !result.quit {
		t.Fatal("selectDefaultProfile() quit = false, want true")
	}
	if !strings.Contains(output.String(), "IAM auth token error: no iam-auth-token-requests configured") {
		t.Fatalf("output = %q, want missing IAM auth token request list message", output.String())
	}
}

func TestRenderDefaultProfileMenuUsesAlignedColumnsAndHeader(t *testing.T) {
	config := Config{
		Credentials: CredentialsConfig{DefaultProfile: "prod"},
		Accounts: []Account{
			{Label: "dev", AccountNumber: "111111111111", IAMRole: "Developer"},
			{Label: "prod", AccountNumber: "222222222222", IAMRole: "Admin"},
		},
	}

	var output bytes.Buffer
	renderDefaultProfileMenu(&output, config, 1, defaultProfileMenuState{})

	rendered := output.String()
	if !strings.Contains(rendered, "go-aws-saml\nSelect the tenant to use as the AWS default profile.\n") {
		t.Fatalf("output = %q, want header", rendered)
	}
	if strings.Contains(rendered, "env=") {
		t.Fatalf("output = %q, should not contain env column", rendered)
	}
	if !strings.Contains(rendered, "  Tenant  Account       Role") {
		t.Fatalf("output = %q, want aligned column header", rendered)
	}
	if !strings.Contains(rendered, "> prod *  222222222222  Admin") {
		t.Fatalf("output = %q, want selected aligned row", rendered)
	}
	if !strings.Contains(rendered, "u to build IAM auth token, q to quit, or d to run in background.") {
		t.Fatalf("output = %q, want updated controls", rendered)
	}
}

func TestRenderIAMAuthTokenRequestMenuUsesAlignedColumns(t *testing.T) {
	config := Config{
		IAMAuthTokenRequests: []IAMAuthTokenConfig{
			{Name: "primary", CacheName: "cache-1", UserID: "user-1"},
			{Name: "secondary", CacheName: "cache-2", UserID: "user-2"},
		},
	}

	var output bytes.Buffer
	renderIAMAuthTokenRequestMenu(&output, config, 1)

	rendered := output.String()
	if !strings.Contains(rendered, "Select the IAM auth token request.") {
		t.Fatalf("output = %q, want IAM auth token request header", rendered)
	}
	if !strings.Contains(rendered, "  Name       Cache    User") {
		t.Fatalf("output = %q, want aligned IAM auth token request columns", rendered)
	}
	if !strings.Contains(rendered, "> secondary  cache-2  user-2") {
		t.Fatalf("output = %q, want selected IAM auth token request row", rendered)
	}
}
