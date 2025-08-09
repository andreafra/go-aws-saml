package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xlzd/gotp"
	"gopkg.in/yaml.v2"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TOTP     string `yaml:"totp"`

	Accounts []Account `yaml:"accounts"`
}

type Account struct {
	Label         string `yaml:"label"`
	IAMRole       string `yaml:"iam-role"`
	SAMLProvider  string `yaml:"saml-provider"`
	Env           string `yaml:"env"`
	AccountNumber string `yaml:"account"`
}

type RoleWithAccount struct {
	Account *Account
	Role    *sts.AssumeRoleWithSAMLOutput
}

const AUnicaAWSSamlURL = "https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=2299"
const AWSLoginSAMLPageURL = "https://signin.aws.amazon.com/saml"
const AWSCredentialsFile = ".aws/credentials"

type AssumeRoleWithSAMLInput = sts.AssumeRoleWithSAMLInput

func main() {
	credentials := readCredentialsFile()
	samlResponseChan := make(chan string, 1)

	authenticateWithBrowser(credentials, samlResponseChan)

	// Block unless we have a response
	samlResponse := <-samlResponseChan

	rolesWithAccount := make([]*RoleWithAccount, 0, len(credentials.Accounts))

	for _, account := range credentials.Accounts {
		role := assumeRole(account, samlResponse)

		rolesWithAccount = append(rolesWithAccount, &RoleWithAccount{
			Account: &account,
			Role:    role,
		})
	}

	writeRolesToAWSCredentialsFile(rolesWithAccount)
}

func readCredentialsFile() Credentials {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	configpath := filepath.Join(userHomeDir, ".go-aws-saml.yml")
	credentialsFile, err := os.ReadFile(configpath)
	if err != nil {
		log.Print("File '.go-aws-saml' not found in user's home directory.")
		log.Fatal(err)
	}

	var credentials Credentials

	err = yaml.Unmarshal(credentialsFile, &credentials)
	if err != nil {
		log.Fatal(err)
	}

	return credentials
}

func authenticateWithBrowser(credentials Credentials, samlResponseChan chan<- string) {

	// Setup TOTP
	totp := gotp.NewDefaultTOTP(credentials.TOTP)

	// Chrome DP
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		//chromedp.WithDebugf(log.Printf),
	)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err := chromedp.RunResponse(ctx,
		chromedp.Navigate(AUnicaAWSSamlURL),
		// wait for page load
		chromedp.WaitVisible(`.ingressoPolimi`),
		chromedp.SetAttributeValue(`#login`, `value`, credentials.Username),
		chromedp.SetAttributeValue(`#password`, `value`, credentials.Password),
		chromedp.Click(`.aunicalogin-button-accedi > button`),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Username & Password validated")
	_, err = chromedp.RunResponse(ctx,
		chromedp.WaitVisible(`#otp`),
		chromedp.SetAttributeValue(`#otp`, `value`, totp.Now()),
		chromedp.Click(`#submit-dissms`),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TOTP validated")

	listenCtx, listenCancel := context.WithTimeout(ctx, 10*time.Second)

	// Listen for requests
	log.Println("Listening for SAML POST Requests...")
	chromedp.ListenTarget(listenCtx, func(ev any) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			req := ev.Request
			log.Printf("%s - %s - %v", req.Method, req.URL, req.PostDataEntries)
			if req.Method == "POST" && strings.HasPrefix(req.URL, AWSLoginSAMLPageURL) {
				listenCancel()

				requestBody := req.PostDataEntries[0].Bytes

				decodedRequestBody, err := base64.StdEncoding.DecodeString(string(requestBody))
				if err != nil {
					log.Fatalf("Failed to decode request body: %v", err)
				}

				parsedBody, err := url.ParseQuery(string(decodedRequestBody))
				if err != nil {
					log.Fatalf("Failed to parse request body: %v", err)
				}

				samlResponseBase64 := parsedBody.Get("SAMLResponse")
				if samlResponseBase64 == "" {
					log.Fatal("SAMLResponse is empty")
				}

				samlResponseChan <- samlResponseBase64
			}
		}
	})
}

func assumeRole(account Account, samlResponse string) *sts.AssumeRoleWithSAMLOutput {
	ctx := context.Background()

	config, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS configuration: %v", err)
	}

	if config.Region == "" {
		log.Fatal(
			`Please make sure to set an AWS region in your AWS CLI configuration.`,
			`You can set the region using the following command:

			aws configure set region <region>

			`,
			`For example:

			aws configure set region us-east-1

			`)
	}

	sts := sts.NewFromConfig(config)

	assumeRoleInput := &AssumeRoleWithSAMLInput{
		RoleArn:       aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", account.AccountNumber, account.IAMRole)),
		PrincipalArn:  aws.String(fmt.Sprintf("arn:aws:iam::%s:saml-provider/%s", account.AccountNumber, account.SAMLProvider)),
		SAMLAssertion: aws.String(samlResponse),
	}

	assumeRoleOutput, err := sts.AssumeRoleWithSAML(ctx, assumeRoleInput)
	if err != nil {
		log.Fatal(err)
	}

	return assumeRoleOutput
}

func writeRolesToAWSCredentialsFile(roles []*RoleWithAccount) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	credentialsFilePath := filepath.Join(userHomeDir, AWSCredentialsFile)

	// Create backup file
	previousData, err := os.ReadFile(credentialsFilePath)
	if err != nil {
		log.Fatal(err)
	}

	const perm = 0600

	os.WriteFile(credentialsFilePath+".bak", previousData, perm)

	os.WriteFile(credentialsFilePath, nil, perm)
	fileD, err := os.OpenFile(credentialsFilePath, os.O_APPEND, perm)
	if err != nil {
		log.Fatal(err)
	}
	defer fileD.Close()

	for i, roleWithAccount := range roles {
		role := roleWithAccount.Role
		account := roleWithAccount.Account
		if i > 0 {
			fmt.Fprintf(fileD, "\n\n")
		}
		fmt.Fprintf(fileD, "\n[profile %s]\n", account.Label)
		fmt.Fprintf(fileD, "aws_access_key_id = %s\n", *role.Credentials.AccessKeyId)
		fmt.Fprintf(fileD, "aws_secret_access_key = %s\n", *role.Credentials.SecretAccessKey)
		fmt.Fprintf(fileD, "aws_session_token = %s\n", *role.Credentials.SessionToken)
	}

	log.Println("AWS credentials file updated successfully.")
}
