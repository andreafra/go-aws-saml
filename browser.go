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
)

const (
	awsLoginSAMLPageURL = "https://signin.aws.amazon.com/saml"
	browserTimeout      = 120 * time.Second
	browserCloseTimeout = 10 * time.Second
)

func authenticateWithBrowser(config Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), browserTimeout)
	defer cancel()

	samlResponseChan := make(chan string, 1)
	samlErrorChan := make(chan error, 1)
	opts, err := browserAllocatorOptions(config)
	if err != nil {
		return "", err
	}
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

	debugLog(config, "Navigating to %s", config.Browser.StartingURL)

	actions := []chromedp.Action{chromedp.Navigate(config.Browser.StartingURL)}
	if config.Browser.ManualLogin {
		log.Printf("Complete the login in the browser within %v", browserTimeout)
		backgroundSessionLogf("Complete the login in the browser within %v", browserTimeout)
	} else {
		totp := gotp.NewDefaultTOTP(config.Credentials.TOTP)
		totpWaitSelector := fallbackSelector(config.Browser.TOTP.WaitForSelector, config.Browser.TOTP.TOTPSelector)
		debugLog(config, "Using login wait selector %q", config.Browser.Login.WaitForSelector)
		debugLog(config, "Using TOTP wait selector %q", totpWaitSelector)
		actions = append(actions,
			chromedp.WaitVisible(config.Browser.Login.WaitForSelector),
			chromedp.SendKeys(config.Browser.Login.UsernameSelector, config.Credentials.Username),
			chromedp.SendKeys(config.Browser.Login.PasswordSelector, config.Credentials.Password),
			chromedp.Click(config.Browser.Login.SubmitSelector),
			chromedp.WaitVisible(totpWaitSelector),
			chromedp.SendKeys(config.Browser.TOTP.TOTPSelector, totp.Now()),
			chromedp.Click(config.Browser.TOTP.SubmitSelector),
		)
	}
	if err := runBrowserActions(chromedpCtx, actions...); err != nil {
		return "", err
	}

	debugLog(config, "Waiting for SAML response")

	samlResponse, err := waitForSAMLResponse(ctx, samlResponseChan, samlErrorChan, config.Browser.ManualLogin)
	if err != nil {
		return "", err
	}
	debugLog(config, "Closing browser contexts after SAML capture")
	if config.Browser.ManualLogin {
		if err := closeBrowser(chromedpCtx); err != nil {
			return "", err
		}
	}
	runtimeDebugLogln("Login successful")
	return samlResponse, nil
}

func runBrowserActions(ctx context.Context, actions ...chromedp.Action) error {
	if err := chromedp.Run(ctx, actions...); err != nil {
		return fmt.Errorf("authenticate in browser: %w", err)
	}
	return nil
}

func closeBrowser(ctx context.Context) error {
	closeCtx, cancel := context.WithTimeout(ctx, browserCloseTimeout)
	defer cancel()
	if err := chromedp.Cancel(closeCtx); err != nil {
		return fmt.Errorf("close browser: %w", err)
	}
	return nil
}

func waitForSAMLResponse(ctx context.Context, responseChan <-chan string, errorChan <-chan error, manualLogin bool) (string, error) {
	var timeout <-chan time.Time
	if !manualLogin {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case samlResponse := <-responseChan:
		return samlResponse, nil
	case err := <-errorChan:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("wait for SAML response: %w", ctx.Err())
	case <-timeout:
		return "", fmt.Errorf("timed out waiting for SAML response")
	}
}

func browserAllocatorOptions(config Config) ([]chromedp.ExecAllocatorOption, error) {
	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", config.Browser.headlessEnabled()),
	)
	if config.Browser.ExecutablePath != "" {
		opts = append(opts, chromedp.ExecPath(config.Browser.ExecutablePath))
	}
	if config.Browser.ManualLogin {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("resolve browser profile directory: %w", err)
		}
		profileDir := filepath.Join(configDir, "go-aws-saml", "browser-profile")
		if err := os.MkdirAll(profileDir, 0700); err != nil {
			return nil, fmt.Errorf("create browser profile directory %q: %w", profileDir, err)
		}
		opts = append(opts, chromedp.UserDataDir(profileDir))
	}

	return opts, nil
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
