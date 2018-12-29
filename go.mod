// +heroku goVersion go1.11
// +heroku install ./cmd/...

module github.com/voutasaurus/oauthtest

go 1.12

require (
	cloud.google.com/go v0.34.0 // indirect
	github.com/voutasaurus/env v0.1.0
	github.com/voutasaurus/oauth v0.0.0-20181229014926-7d1278485b55
	golang.org/x/oauth2 v0.0.0-20181203162652-d668ce993890
)
