package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xlzd/gotp"
)

const (
	awsLoginSAMLPageURL = "https://signin.aws.amazon.com/saml"
	browserTimeout      = 30 * time.Second
)

func authenticateWithBrowser(config Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), browserTimeout)
	defer cancel()

	totp := gotp.NewDefaultTOTP(config.Credentials.TOTP)
	samlResponseChan := make(chan string, 1)
	samlErrorChan := make(chan error, 1)
	opts := browserAllocatorOptions(config)
	headless := config.Browser.headlessEnabled()

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	chromedpCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	runtimeDebugLogf("Starting browser authentication (headless=%t, debug=%t, executable=%q)", headless, config.Browser.Debug, config.Browser.ExecutablePath)
	debugLog(config, "Listening for SAML POST requests")
	chromedp.ListenTarget(chromedpCtx, func(ev any) {
		request, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || request.Request.Method != "POST" || !strings.HasPrefix(request.Request.URL, awsLoginSAMLPageURL) {
			return
		}

		debugLog(config, "Captured POST request to %s", request.Request.URL)
		samlResponse, err := samlResponseFromRequest(request.Request.PostDataEntries)
		if err != nil {
			sendSAMLResponseError(samlErrorChan, err)
			return
		}

		debugLog(config, "Decoded SAML response")
		sendSAMLResponse(samlResponseChan, samlResponse)
	})

	actionCtx, actionCancel := context.WithTimeout(chromedpCtx, browserTimeout)
	defer actionCancel()

	totpWaitSelector := fallbackSelector(config.Browser.TOTP.WaitForSelector, config.Browser.TOTP.TOTPSelector)
	debugLog(config, "Using login wait selector %q", config.Browser.Login.WaitForSelector)
	debugLog(config, "Using TOTP wait selector %q", totpWaitSelector)
	debugLog(config, "Navigating to %s", config.Browser.StartingURL)

	if err := chromedp.Run(actionCtx,
		chromedp.Navigate(config.Browser.StartingURL),
		chromedp.WaitVisible(config.Browser.Login.WaitForSelector),
		chromedp.SendKeys(config.Browser.Login.UsernameSelector, config.Credentials.Username),
		chromedp.SendKeys(config.Browser.Login.PasswordSelector, config.Credentials.Password),
		chromedp.Click(config.Browser.Login.SubmitSelector),
		chromedp.WaitVisible(totpWaitSelector),
		chromedp.SendKeys(config.Browser.TOTP.TOTPSelector, totp.Now()),
		chromedp.Click(config.Browser.TOTP.SubmitSelector),
	); err != nil {
		return "", fmt.Errorf("authenticate in browser: %w", err)
	}

	debugLog(config, "Submitted login and TOTP forms, waiting for SAML response")

	select {
	case samlResponse := <-samlResponseChan:
		debugLog(config, "Closing browser contexts after SAML capture")
		actionCancel()
		browserCancel()
		allocCancel()
		runtimeDebugLogln("Login successful")
		return samlResponse, nil
	case err := <-samlErrorChan:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("wait for SAML response: %w", ctx.Err())
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timed out waiting for SAML response")
	}
}

func browserAllocatorOptions(config Config) []chromedp.ExecAllocatorOption {
	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", config.Browser.headlessEnabled()),
	)
	if config.Browser.ExecutablePath != "" {
		opts = append(opts, chromedp.ExecPath(config.Browser.ExecutablePath))
	}

	return opts
}

func debugLog(config Config, format string, args ...any) {
	if !config.Browser.Debug {
		return
	}

	runtimeDebugLogf("DEBUG "+format, args...)
}

func fallbackSelector(selector string, fallback string) string {
	if selector != "" {
		return selector
	}

	return fallback
}

func samlResponseFromRequest(entries []*network.PostDataEntry) (string, error) {
	if len(entries) == 0 {
		return "", fmt.Errorf("SAML request does not contain POST data")
	}

	decodedRequestBody, err := base64.StdEncoding.DecodeString(entries[0].Bytes)
	if err != nil {
		return "", fmt.Errorf("decode SAML request body: %w", err)
	}

	parsedBody, err := url.ParseQuery(string(decodedRequestBody))
	if err != nil {
		return "", fmt.Errorf("parse SAML request body: %w", err)
	}

	samlResponseBase64 := parsedBody.Get("SAMLResponse")
	if samlResponseBase64 == "" {
		return "", fmt.Errorf("SAMLResponse is empty")
	}

	return samlResponseBase64, nil
}

func sendSAMLResponse(responseChan chan<- string, samlResponse string) {
	select {
	case responseChan <- samlResponse:
	default:
	}
}

func sendSAMLResponseError(errorChan chan<- error, err error) {
	select {
	case errorChan <- err:
	default:
	}
}
