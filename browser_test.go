package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func TestSAMLResponseFromRequest(t *testing.T) {
	requestBody := url.Values{
		"SAMLResponse": {"encoded-saml-response"},
		"RelayState":   {"relay-state"},
	}.Encode()

	got, err := samlResponseFromRequest([]*network.PostDataEntry{
		{Bytes: base64.StdEncoding.EncodeToString([]byte(requestBody))},
	})
	if err != nil {
		t.Fatalf("samlResponseFromRequest() error = %v", err)
	}
	if got != "encoded-saml-response" {
		t.Fatalf("samlResponseFromRequest() = %q, want encoded-saml-response", got)
	}
}

func TestFallbackSelector(t *testing.T) {
	if got := fallbackSelector("#configured", "#fallback"); got != "#configured" {
		t.Fatalf("fallbackSelector() = %q, want #configured", got)
	}
	if got := fallbackSelector("", "#fallback"); got != "#fallback" {
		t.Fatalf("fallbackSelector() = %q, want #fallback", got)
	}
}

func TestManualLoginWaitsBeyondAutomaticTimeout(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	responses := make(chan string, 1)
	timer := time.AfterFunc(5200*time.Millisecond, func() { responses <- "assertion" })
	defer timer.Stop()

	got, err := waitForSAMLResponse(ctx, responses, make(chan error), true)
	if err != nil || got != "assertion" {
		t.Fatalf("waitForSAMLResponse() = %q, %v; want assertion, nil", got, err)
	}
}

func TestAutomaticLoginStillTimesOut(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := waitForSAMLResponse(ctx, make(chan string), make(chan error), false)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for SAML response") {
		t.Fatalf("waitForSAMLResponse() error = %v, want automatic timeout", err)
	}
}

func TestManualLoginHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := waitForSAMLResponse(ctx, make(chan string), make(chan error), true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForSAMLResponse() error = %v, want context.Canceled", err)
	}
}

func testUserConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("AppData", dir)
	case "darwin":
		t.Setenv("HOME", dir)
		dir = filepath.Join(dir, "Library", "Application Support")
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
	return dir
}

func TestBrowserAllocatorOptionsCreatesProfileOnlyForManualLogin(t *testing.T) {
	dir := testUserConfigDir(t)
	profileDir := filepath.Join(dir, "go-aws-saml", "browser-profile")
	if _, err := browserAllocatorOptions(Config{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profileDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("automatic login created a persistent profile or failed to check it: %v", err)
	}
	config := Config{Browser: BrowserConfig{ManualLogin: true}}
	for i := 0; i < 2; i++ {
		if _, err := browserAllocatorOptions(config); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(profileDir); err != nil || !info.IsDir() {
		t.Fatalf("persistent profile directory not created: %v", err)
	}
}

func TestBrowserAllocatorOptionsReportsProfileCreationFailure(t *testing.T) {
	dir := testUserConfigDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go-aws-saml"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := browserAllocatorOptions(Config{Browser: BrowserConfig{ManualLogin: true}})
	if err == nil || !strings.Contains(err.Error(), "create browser profile directory") {
		t.Fatalf("browserAllocatorOptions() error = %v, want profile creation error", err)
	}
}

func TestManualBrowserProfilePersistsCookies(t *testing.T) {
	browserPath := os.Getenv("GO_AWS_SAML_TEST_BROWSER")
	if browserPath == "" {
		t.Skip("set GO_AWS_SAML_TEST_BROWSER to test browser profile persistence")
	}
	testUserConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "test_session", Value: "saved", Path: "/", MaxAge: 3600})
		}
	}))
	defer server.Close()

	config := Config{Browser: BrowserConfig{ManualLogin: true, ExecutablePath: browserPath}}
	runBrowser := func(path string) string {
		t.Helper()
		opts, err := browserAllocatorOptions(config)
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, chromedp.Flag("headless", true))
		allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
		ctx, cancel := chromedp.NewContext(allocCtx)
		defer allocCancel()
		defer cancel()
		var cookie string
		if err := runBrowserActions(ctx, chromedp.Navigate(server.URL+path), chromedp.Evaluate("document.cookie", &cookie)); err != nil {
			t.Fatal(err)
		}
		if err := closeBrowser(ctx); err != nil {
			t.Fatal(err)
		}
		return cookie
	}
	if got := runBrowser("/set"); !strings.Contains(got, "test_session=saved") {
		t.Fatalf("first browser cookie = %q", got)
	}
	if got := runBrowser("/check"); !strings.Contains(got, "test_session=saved") {
		t.Fatalf("second browser cookie = %q; persistent cookie was not reused", got)
	}
}
