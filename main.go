package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	loadConfigFileFn                 = loadConfigFile
	writeConfigFileFn                = writeConfigFile
	selectDefaultProfileFn           = selectDefaultProfile
	authenticateWithBrowserFn        = authenticateWithBrowser
	assumeRolesFn                    = assumeRoles
	writeRolesToAWSCredentialsFileFn = writeRolesToAWSCredentialsFile
	startBackgroundProcessFn         = startBackgroundProcess
	reattachBackgroundSessionFn      = reattachBackgroundSession
	runManagedBackgroundSessionFn    = runManagedBackgroundSession
	signSelectedTenantURLFn          = signSelectedTenantURL
	buildIAMAuthTokenFn              = buildIAMAuthToken
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("go-aws-saml", flag.ContinueOnError)
	flags.SetOutput(stdout)

	selectDefault := flags.Bool("select-default", false, "choose the account written as the AWS default profile")
	backgroundRun := flags.Bool("background-run", false, "")
	signURL := flags.String("sign-url", "", "generate a SigV4-signed URL using the selected tenant credentials")
	signService := flags.String("sign-service", "elasticache", "AWS service name to use for SigV4 signing")
	signRegion := flags.String("sign-region", "", "AWS region to use for SigV4 signing; defaults to the selected profile region")
	signMethod := flags.String("sign-method", http.MethodGet, "HTTP method to use for SigV4 signing")
	signExpires := flags.Int("sign-expires", defaultSignURLExpiresSeconds, "expiration for the signed URL in seconds")
	if err := flags.Parse(args); err != nil {
		return err
	}

	configPath, err := defaultConfigPath()
	if err != nil {
		return err
	}

	config, err := loadConfigFileFn(configPath, stdin, stdout)
	if err != nil {
		return err
	}

	if *selectDefault {
		result, err := selectDefaultProfileFn(stdin, stdout, &config)
		if err != nil {
			return err
		}
		if !result.changed {
			return nil
		}
		if err := writeConfigFileFn(configPath, config); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Saved %s with credentials.default = %q\n", configPath, config.Credentials.DefaultProfile)
		return nil
	}

	if *signURL != "" {
		signedURL, err := signSelectedTenantURLFn(config, *signURL, *signService, *signRegion, *signMethod, *signExpires)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stdout, signedURL)
		return nil
	}

	if err := validateRuntimeConfig(config); err != nil {
		return err
	}

	setRuntimeDebugLogging(config.Browser.Debug)

	if *backgroundRun {
		return runManagedBackgroundSessionFn(stdin, stdout, configPath, &config)
	}

	if attached, err := reattachBackgroundSessionFn(stdout); err != nil {
		return err
	} else if attached {
		return nil
	}

	return runRefreshLoop(stdin, stdout, configPath, &config, true, true)
}

func runRefreshLoop(stdin io.Reader, stdout io.Writer, configPath string, config *Config, promptForDefault bool, initialRefresh bool) error {
	refreshTicker := time.NewTicker(time.Duration(config.RefreshInterval) * time.Second)
	defer refreshTicker.Stop()

	if initialRefresh {
		backgroundSessionLogf("running initial refresh")
		backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(stdin, stdout, configPath, config, promptForDefault)
		if err != nil {
			backgroundSessionLogf("initial refresh failed: %v", err)
			return err
		}
		backgroundSessionLogf("initial refresh completed")
		if quitRequested {
			return nil
		}
		if backgroundRequested {
			if err := startBackgroundProcessFn(); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "Background refresh started.")
			return nil
		}
	}

	for range refreshTicker.C {
		backgroundSessionLogf("running scheduled refresh")
		backgroundRequested, quitRequested, err := refreshCredentialsWithSAML(stdin, stdout, configPath, config, false)
		if err != nil {
			backgroundSessionLogf("scheduled refresh failed: %v", err)
			return err
		}
		backgroundSessionLogf("scheduled refresh completed")
		if quitRequested {
			return nil
		}
		if backgroundRequested {
			if err := startBackgroundProcessFn(); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "Background refresh started.")
			return nil
		}
	}

	return nil
}

func refreshCredentialsWithSAML(stdin io.Reader, stdout io.Writer, configPath string, config *Config, promptForDefault bool) (bool, bool, error) {
	runtimeDebugLogln("Refreshing credentials...")

	samlResponse, err := authenticateWithBrowserFn(*config)
	if err != nil {
		return false, false, err
	}

	backgroundRequested := false
	quitRequested := false
	if promptForDefault {
		result, err := selectDefaultProfileFn(stdin, stdout, config)
		if err != nil {
			return false, false, err
		}
		if result.changed {
			if err := writeConfigFileFn(configPath, *config); err != nil {
				return false, false, err
			}
			_, _ = fmt.Fprintf(stdout, "Saved %s with credentials.default = %q\n", configPath, config.Credentials.DefaultProfile)
		}
		backgroundRequested = result.background
		quitRequested = result.quit
	}

	roles, err := assumeRolesFn(config.Region, config.Accounts, samlResponse)
	if err != nil {
		return false, false, err
	}

	if err := writeRolesToAWSCredentialsFileFn(roles, config.Credentials.DefaultProfile); err != nil {
		return false, false, err
	}

	runtimeDebugLogf("Next refresh in %v", time.Duration(config.RefreshInterval)*time.Second)
	return backgroundRequested, quitRequested, nil
}
