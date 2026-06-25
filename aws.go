package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type RoleWithAccount struct {
	Account Account
	Role    *sts.AssumeRoleWithSAMLOutput
}

type samlRoleAssumer interface {
	AssumeRoleWithSAML(context.Context, *sts.AssumeRoleWithSAMLInput, ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
}

func assumeRoles(region string, accounts []Account, samlResponse string) ([]RoleWithAccount, error) {
	ctx := context.Background()

	loadOptions := []func(*awsconfig.LoadOptions) error{}
	if defaultRegion := normalizedRegionValue(region); defaultRegion != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(defaultRegion))
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}

	if awsConfig.Region == "" {
		return nil, fmt.Errorf("AWS region is not configured; set region in %s or run `aws configure set region <region>`", configFileName)
	}

	stsClient := sts.NewFromConfig(awsConfig)
	roles := make([]RoleWithAccount, 0, len(accounts))

	for _, account := range accounts {
		role, err := assumeRole(ctx, stsClient, account, samlResponse)
		if err != nil {
			return nil, err
		}

		roles = append(roles, RoleWithAccount{
			Account: account,
			Role:    role,
		})
	}

	return roles, nil
}

func assumeRole(ctx context.Context, client samlRoleAssumer, account Account, samlResponse string) (*sts.AssumeRoleWithSAMLOutput, error) {
	assumeRoleInput := &sts.AssumeRoleWithSAMLInput{
		RoleArn:       aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", account.AccountNumber, account.IAMRole)),
		PrincipalArn:  aws.String(fmt.Sprintf("arn:aws:iam::%s:saml-provider/%s", account.AccountNumber, account.SAMLProvider)),
		SAMLAssertion: aws.String(samlResponse),
	}

	assumeRoleOutput, err := client.AssumeRoleWithSAML(ctx, assumeRoleInput)
	if err != nil {
		return nil, fmt.Errorf("assume role %q for account %s: %w", account.IAMRole, account.AccountNumber, err)
	}

	return assumeRoleOutput, nil
}
