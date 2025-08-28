module github.com/jbuchbinder/go-git-crypt

go 1.23.0

toolchain go1.24.3

replace github.com/jbuchbinder/go-git-crypt/gpg => ./gpg

require (
	github.com/ProtonMail/go-crypto v1.3.0
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-20250212141212-325ebd1e616b
	golang.org/x/crypto v0.41.0
	golang.org/x/tools v0.36.0
)

require (
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
