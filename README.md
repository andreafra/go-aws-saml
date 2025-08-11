# go-aws-saml

This is a program that automates the process of assuming AWS roles using SAML authentication.

As you know, the AWS CLI does not support SAML authentication out of the box.
In fact, it's rather tedious to do this manually.

This program provides a simple way to assume AWS roles using SAML authentication.

## Usage

You need to create the following file in your user home directory:

```
~/.go-aws-saml.yml
```

```yaml
refresh-in-seconds: 3500 # a little less than the default AWS session duration

credentials:
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
  login:
    wait-for-selector: <the selector that waits for the login page to load>
    username-selector: "#username" # the username input field
    password-selector: "#password" # the password input field
    submit-selector: "#submit-login" # the login button
  totp:
    totp-selector: //*[@id="otp"] # the 2FA input field - you can also use XPath
    submit-selector: "#submit-dissms" # the 2FA submit button
```
