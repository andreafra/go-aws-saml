package main

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/chromedp/cdproto/network"
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
