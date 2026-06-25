package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func defaultAWSCredentialsPath() (string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home directory: %w", err)
	}

	return filepath.Join(userHomeDir, ".aws", "credentials"), nil
}

func writeRolesToAWSCredentialsFile(roles []RoleWithAccount, defaultProfile string) error {
	credentialsFilePath, err := defaultAWSCredentialsPath()
	if err != nil {
		return err
	}

	return writeRolesToCredentialsFile(credentialsFilePath, roles, defaultProfile)
}

func writeRolesToCredentialsFile(credentialsFilePath string, roles []RoleWithAccount, defaultProfile string) error {
	if err := os.MkdirAll(filepath.Dir(credentialsFilePath), 0700); err != nil {
		return fmt.Errorf("create AWS credentials directory: %w", err)
	}

	if err := backupFile(credentialsFilePath); err != nil {
		return err
	}

	fileD, err := os.OpenFile(credentialsFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open AWS credentials file for writing: %w", err)
	}
	defer fileD.Close()

	if err := writeCredentialProfiles(fileD, roles, defaultProfile); err != nil {
		return err
	}

	runtimeDebugLogln("AWS credentials file updated successfully.")
	runtimeDebugLogln("Select your profile using `export AWS_PROFILE=<profile name>`")
	return nil
}

func backupFile(path string) error {
	previousData, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing AWS credentials file for backup: %w", err)
	}

	if err := os.WriteFile(path+".bak", previousData, 0600); err != nil {
		return fmt.Errorf("write AWS credentials backup file: %w", err)
	}

	return nil
}

func writeCredentialProfiles(writer io.Writer, roles []RoleWithAccount, defaultProfile string) error {
	defaultRoleIndex, err := defaultRoleIndex(roles, defaultProfile)
	if err != nil {
		return err
	}

	hasDefaultProfile := defaultRoleIndex >= 0
	if hasDefaultProfile {
		credentials, err := roleCredentials(roles[defaultRoleIndex], "default")
		if err != nil {
			return err
		}
		if err := writeCredentialProfile(writer, "default", credentials); err != nil {
			return err
		}
		logRole(roles[defaultRoleIndex], "default")
	}

	for i, roleWithAccount := range roles {
		if hasDefaultProfile || i > 0 {
			if _, err := fmt.Fprint(writer, "\n"); err != nil {
				return err
			}
		}

		credentials, err := roleCredentials(roleWithAccount, roleWithAccount.Account.Label)
		if err != nil {
			return err
		}
		if err := writeCredentialProfile(writer, roleWithAccount.Account.Label, credentials); err != nil {
			return err
		}
		logRole(roleWithAccount, roleWithAccount.Account.Label)
	}

	return nil
}

func defaultRoleIndex(roles []RoleWithAccount, defaultProfile string) (int, error) {
	if defaultProfile == "" {
		return -1, nil
	}

	for i, role := range roles {
		if role.Account.Label == defaultProfile {
			return i, nil
		}
	}

	return -1, fmt.Errorf("credentials.default %q does not match any configured account label", defaultProfile)
}

func roleCredentials(roleWithAccount RoleWithAccount, profileName string) (*types.Credentials, error) {
	if roleWithAccount.Role == nil || roleWithAccount.Role.Credentials == nil {
		return nil, fmt.Errorf("AWS credentials for profile %q are empty", profileName)
	}

	return roleWithAccount.Role.Credentials, nil
}

func writeCredentialProfile(writer io.Writer, profileName string, credentials *types.Credentials) error {
	if credentials == nil {
		return fmt.Errorf("AWS credentials for profile %q are empty", profileName)
	}

	if _, err := fmt.Fprintf(writer, "[%s]\n", profileName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "aws_access_key_id = %s\n", value(credentials.AccessKeyId)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "aws_secret_access_key = %s\n", value(credentials.SecretAccessKey)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "aws_session_token = %s\n", value(credentials.SessionToken)); err != nil {
		return err
	}

	return nil
}

func value(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func logRole(roleWithAccount RoleWithAccount, profileName string) {
	account := roleWithAccount.Account
	runtimeDebugLogf(" * Add profile for '%s' (env=%s) [%s - %s]", profileName, account.Env, account.AccountNumber, account.IAMRole)

	if roleWithAccount.Role == nil || roleWithAccount.Role.Credentials == nil {
		return
	}

	expiration := roleWithAccount.Role.Credentials.Expiration
	if expiration != nil {
		runtimeDebugLogf("   expiring in %v", time.Until(*expiration))
	}
}
