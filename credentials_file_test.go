package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestWriteCredentialProfilesWritesDefaultAlias(t *testing.T) {
	roles := []RoleWithAccount{
		testRole("dev", "development", "111111111111", "Developer", "DEVKEY"),
		testRole("prod", "production", "222222222222", "Admin", "PRODKEY"),
	}

	var output bytes.Buffer
	if err := writeCredentialProfiles(&output, roles, "prod"); err != nil {
		t.Fatalf("writeCredentialProfiles() error = %v", err)
	}

	want := strings.Join([]string{
		"[default]",
		"aws_access_key_id = PRODKEY",
		"aws_secret_access_key = PRODKEYSECRET",
		"aws_session_token = PRODKEYTOKEN",
		"",
		"[dev]",
		"aws_access_key_id = DEVKEY",
		"aws_secret_access_key = DEVKEYSECRET",
		"aws_session_token = DEVKEYTOKEN",
		"",
		"[prod]",
		"aws_access_key_id = PRODKEY",
		"aws_secret_access_key = PRODKEYSECRET",
		"aws_session_token = PRODKEYTOKEN",
		"",
	}, "\n")

	if got := output.String(); got != want {
		t.Fatalf("credentials file mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestWriteCredentialProfilesRejectsUnknownDefault(t *testing.T) {
	roles := []RoleWithAccount{
		testRole("dev", "development", "111111111111", "Developer", "DEVKEY"),
	}

	var output bytes.Buffer
	err := writeCredentialProfiles(&output, roles, "prod")
	if err == nil {
		t.Fatal("writeCredentialProfiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "credentials.default") {
		t.Fatalf("error = %q, want credentials.default context", err)
	}
}

func TestWriteCredentialProfilesRejectsMissingCredentials(t *testing.T) {
	roles := []RoleWithAccount{
		{Account: Account{Label: "dev"}},
	}

	var output bytes.Buffer
	err := writeCredentialProfiles(&output, roles, "")
	if err == nil {
		t.Fatal("writeCredentialProfiles() error = nil, want error")
	}
	if !strings.Contains(err.Error(), `profile "dev"`) {
		t.Fatalf("error = %q, want profile context", err)
	}
}

func testRole(label, env, accountNumber, iamRole, accessKey string) RoleWithAccount {
	expiration := time.Now().Add(time.Hour)

	return RoleWithAccount{
		Account: Account{
			Label:         label,
			Env:           env,
			AccountNumber: accountNumber,
			IAMRole:       iamRole,
		},
		Role: &sts.AssumeRoleWithSAMLOutput{
			Credentials: &types.Credentials{
				AccessKeyId:     aws.String(accessKey),
				SecretAccessKey: aws.String(accessKey + "SECRET"),
				SessionToken:    aws.String(accessKey + "TOKEN"),
				Expiration:      aws.Time(expiration),
			},
		},
	}
}
