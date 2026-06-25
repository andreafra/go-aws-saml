package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestSignURLWithCredentials(t *testing.T) {
	credentials := aws.Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
	}

	signedURL, err := signURLWithCredentials(
		credentials,
		"https://cache.example.com/?Action=connect&User=test-user",
		"elasticache",
		"eu-west-1",
		"get",
		900,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("signURLWithCredentials() error = %v", err)
	}

	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	query := parsedURL.Query()
	if got := query.Get("Action"); got != "connect" {
		t.Fatalf("Action = %q, want connect", got)
	}
	if got := query.Get("User"); got != "test-user" {
		t.Fatalf("User = %q, want test-user", got)
	}
	if got := query.Get("X-Amz-Algorithm"); got != "AWS4-HMAC-SHA256" {
		t.Fatalf("X-Amz-Algorithm = %q, want AWS4-HMAC-SHA256", got)
	}
	if got := query.Get("X-Amz-Expires"); got != "900" {
		t.Fatalf("X-Amz-Expires = %q, want 900", got)
	}
	if got := query.Get("X-Amz-Security-Token"); got != "session-token" {
		t.Fatalf("X-Amz-Security-Token = %q, want session-token", got)
	}
	if got := query.Get("X-Amz-Credential"); !strings.Contains(got, "/eu-west-1/elasticache/aws4_request") {
		t.Fatalf("X-Amz-Credential = %q, want region/service scope", got)
	}
	if got := query.Get("X-Amz-Signature"); got == "" {
		t.Fatal("X-Amz-Signature is empty")
	}
}

func TestSignURLWithCredentialsRejectsInvalidExpires(t *testing.T) {
	_, err := signURLWithCredentials(aws.Credentials{}, "https://example.com", "elasticache", "eu-west-1", "GET", 0, time.Now())
	if err == nil {
		t.Fatal("signURLWithCredentials() error = nil, want error")
	}
}

func TestBuildIAMAuthTokenRequestShape(t *testing.T) {
	credentials := aws.Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token",
	}

	signedURL, err := signURLWithCredentials(
		credentials,
		"http://cache-01/?Action=connect&ResourceType=ServerlessCache&User=iam-user",
		"elasticache",
		"eu-west-1",
		"GET",
		defaultSignURLExpiresSeconds,
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("signURLWithCredentials() error = %v", err)
	}

	token := strings.TrimPrefix(signedURL, "http://")
	if strings.HasPrefix(token, "http://") {
		t.Fatalf("token = %q, should not include http://", token)
	}
	if !strings.Contains(token, "Action=connect") {
		t.Fatalf("token = %q, want Action=connect", token)
	}
	if !strings.Contains(token, "ResourceType=ServerlessCache") {
		t.Fatalf("token = %q, want ResourceType=ServerlessCache", token)
	}
}
