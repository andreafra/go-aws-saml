package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const defaultSignURLExpiresSeconds = 900
const iamAuthTokenRequestMethod = http.MethodGet

func signSelectedTenantURL(config Config, rawURL string, service string, region string, method string, expiresSeconds int) (string, error) {
	profile := config.Credentials.DefaultProfile
	if profile == "" {
		return "", fmt.Errorf("credentials.default is empty; select a tenant first")
	}

	return signTenantURL(config, profile, rawURL, service, region, method, expiresSeconds)
}

func buildIAMAuthToken(config Config, profile string, requestConfig IAMAuthTokenConfig) (string, error) {
	if profile == "" {
		return "", fmt.Errorf("tenant profile is empty")
	}
	cacheName := strings.TrimSpace(requestConfig.CacheName)
	if cacheName == "" {
		return "", fmt.Errorf("iam-auth-token-requests[].cache-name is empty in %s", configFileName)
	}
	userID := strings.TrimSpace(requestConfig.UserID)
	if userID == "" {
		return "", fmt.Errorf("iam-auth-token-requests[].user-id is empty in %s", configFileName)
	}

	query := url.Values{}
	query.Set("Action", "connect")
	query.Set("User", userID)
	if requestConfig.IsServerless {
		query.Set("ResourceType", "ServerlessCache")
	}

	rawURL := (&url.URL{
		Scheme:   "http",
		Host:     cacheName,
		Path:     "/",
		RawQuery: query.Encode(),
	}).String()

	tokenRegion := normalizedRegionValue(requestConfig.Region)
	if tokenRegion == "" {
		tokenRegion = defaultRegionValue(config)
	}

	signedURL, err := signTenantURL(config, profile, rawURL, "elasticache", tokenRegion, iamAuthTokenRequestMethod, defaultSignURLExpiresSeconds)
	if err != nil {
		return "", err
	}

	return strings.TrimPrefix(signedURL, "http://"), nil
}

func signTenantURL(config Config, profile string, rawURL string, service string, region string, method string, expiresSeconds int) (string, error) {
	if profile == "" {
		return "", fmt.Errorf("tenant profile is empty")
	}

	ctx := context.Background()
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithSharedConfigProfile(profile),
	}
	region = normalizedRegionValue(region)
	if region == "" {
		region = defaultRegionValue(config)
	}
	if region != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return "", fmt.Errorf("load AWS configuration for profile %q: %w", profile, err)
	}

	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return "", fmt.Errorf("AWS region is not configured; set region in %s, pass --sign-region, or run `aws configure set region <region>`", configFileName)
	}

	credentials, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("retrieve AWS credentials for profile %q: %w", profile, err)
	}

	return signURLWithCredentials(credentials, rawURL, service, region, method, expiresSeconds, time.Now())
}

func signURLWithCredentials(credentials aws.Credentials, rawURL string, service string, region string, method string, expiresSeconds int, signingTime time.Time) (string, error) {
	if service == "" {
		return "", fmt.Errorf("service must not be empty")
	}
	if expiresSeconds <= 0 {
		return "", fmt.Errorf("expiresSeconds must be greater than 0")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL %q: %w", rawURL, err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", fmt.Errorf("URL %q must include scheme and host", rawURL)
	}

	request, err := http.NewRequest(strings.ToUpper(method), parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build HTTP request: %w", err)
	}

	query := request.URL.Query()
	query.Set("X-Amz-Expires", strconv.Itoa(expiresSeconds))
	request.URL.RawQuery = query.Encode()

	signer := v4.NewSigner()
	signedURL, _, err := signer.PresignHTTP(
		context.Background(),
		credentials,
		request,
		emptyPayloadSHA256(),
		service,
		region,
		signingTime,
	)
	if err != nil {
		return "", fmt.Errorf("sign URL for service %q in region %q: %w", service, region, err)
	}

	return signedURL, nil
}

func emptyPayloadSHA256() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}
