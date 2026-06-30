# go-aws-saml

This is a program that automates the process of assuming AWS roles using SAML authentication.

As you know, the AWS CLI does not support SAML authentication out of the box.
In fact, it's rather tedious to do this manually.

This program provides a simple way to assume AWS roles using SAML authentication.

## Usage

On first run, if the following file is missing, `go-aws-saml` creates it with
default values and opens it in your editor:

```
~/.go-aws-saml.yml
```

```yaml
refresh-in-seconds: 3500 # a little less than the default AWS session duration
region: eu-west-1 # optional; default AWS region for role assumption and signing

credentials:
  default: <the account label to write as the AWS default profile>
  username: <your company username>
  password: <your company password>
  totp: <your 2FA totp code>

accounts:
  - label: <your account label - call this whatever you want>
    iam-role: <your iam role>
    saml-provider: <your saml provider>
    env: <the environment name - call this whatever you want>
    account: <your AWS account number>

browser:
  starting-url: <the starting url that sends you to login>
  executable-path: "" # optional; path to the browser binary, useful on WSL
  headless: true # optional; set to false to display the browser window
  debug: false # optional; set to true to enable debug logs
  login:
    wait-for-selector: <the selector that waits for the login page to load>
    username-selector: "#username" # the username input field
    password-selector: "#password" # the password input field
    submit-selector: "#submit-login" # the login button
  totp:
    wait-for-selector: //*[@id="otp"] # optional; defaults to totp-selector when omitted
    totp-selector: //*[@id="otp"] # the 2FA input field - you can also use XPath
    submit-selector: "#submit-dissms" # the 2FA submit button

iam-auth-token-requests:
  - name: redis-primary
    user-id: iam-user
    cache-name: cache-name
    region: eu-west-1 # optional; defaults to top-level region
    is-serverless: true # optional; adds ResourceType=ServerlessCache
  - name: redis-secondary
    user-id: iam-user-2
    cache-name: cache-name-2
```

The account whose label matches `credentials.default` is also written to the
`[default]` profile in `~/.aws/credentials`.

To change the default profile from the configured accounts:

```bash
go-aws-saml --select-default
```

This updates `credentials.default` in `~/.go-aws-saml.yml`.

In the interactive tenant selector:

- `Up` / `Down` moves the selection
- `Space` / `Enter` sets the selected tenant as default
- `u` opens a second picker for configured IAM auth token requests, then builds the token for the highlighted tenant and selected request
- `q` quits
- `d` starts the refresh loop in the background and returns control to the shell

If a background refresh loop is already running, starting `go-aws-saml` again reattaches to that existing loop instead of launching a second one. Press `Ctrl+C` to detach from the attached view while leaving the background refresh loop running.

You can also generate a signed URL directly:

```bash
go-aws-saml --sign-url 'https://cache.example.com/?Action=connect&User=iam-user'
```

On WSL, `headless: false` only helps if the launched browser can display a GUI.
If you want to use Windows Chrome from WSL, set:

```yaml
browser:
  executable-path: /mnt/c/Program Files/Google/Chrome/Application/chrome.exe
  headless: false
```
