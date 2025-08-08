package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xlzd/gotp"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TOTP     string `yaml:"totp"`

	Accounts []Accounts `yaml:"accounts"`
}

type Accounts struct {
	Name          string `yaml:"name"`
	IAMRole       string `yaml:"iam-role"`
	SAMLProvider  string `yaml:"saml-provider"`
	Env           string `yaml:"env"`
	AccountNumber string `yaml:"account"`
}

const AUnicaAWSSamlURL = "https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=2299"
const AWSLoginSAMLPageURL = "https://signin.aws.amazon.com/saml"
const SAMLResponsePrefix = "SAMLResponse="

func main() {

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

	totp := gotp.NewDefaultTOTP(credentials.TOTP)

	// Chrome DP
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		//chromedp.WithDebugf(log.Printf),
	)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := chromedp.RunResponse(ctx,
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
	log.Println(resp)
	resp, err = chromedp.RunResponse(ctx,
		chromedp.WaitVisible(`#otp`),
		chromedp.SetAttributeValue(`#otp`, `value`, totp.Now()),
		chromedp.Click(`#submit-dissms`),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TOTP validated")
	log.Println(resp)

	listenCtx, listenCancel := context.WithTimeout(ctx, 10*time.Second)

	samlResponseChan := make(chan string, 1)

	// Listen for requests
	chromedp.ListenTarget(listenCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			req := ev.Request
			log.Printf("%s - %s - %v", req.Method, req.URL, req.PostDataEntries)
			if req.Method == "POST" && strings.HasPrefix(req.URL, AWSLoginSAMLPageURL) {
				listenCancel()

				samlResponseBase64 := req.PostDataEntries[0].Bytes

				samlResponse, err := base64.StdEncoding.DecodeString(samlResponseBase64)
				if err != nil {
					log.Fatal(err)
				}
				samlResponseStr := string(samlResponse)
				log.Printf("SAML Response: %s", samlResponseStr)
				if strings.HasPrefix(samlResponseStr, SAMLResponsePrefix) {
					samlResponseChan <- strings.TrimPrefix(SAMLResponsePrefix, samlResponseStr)
				}
			}
		}
	})

	// Block unless we have a response
	samlResponse := <-samlResponseChan

	println("Assuming role using AWS CLI")
	for _, account := range credentials.Accounts {
		assumeRoleCmdInput := fmt.Sprintf(`aws sts assume-role-with-saml
            --role-arn arn:aws:iam::%s:role/%s
            --principal-arn arn:aws:iam::%s:saml-provider/%s
            --saml-assertion "%s"`, account.AccountNumber, account.IAMRole, account.AccountNumber, account.SAMLProvider, samlResponse)

		cmd := exec.Command(assumeRoleCmdInput)

		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb

		if err := cmd.Run(); err != nil {
			log.Println(err)
		}
		fmt.Println("out:", outb.String(), "err:", errb.String())
	}

}
