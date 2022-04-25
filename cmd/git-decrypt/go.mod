module github.com/jbuchbinder/go-git-crypt/cmd/git-decrypt

go 1.16

replace (
	github.com/jbuchbinder/go-git-crypt => ../..
	github.com/jbuchbinder/go-git-crypt/gpg => ../../gpg
)

require (
	github.com/jbuchbinder/go-git-crypt v0.0.0-20210513122809-c18a4d41886e
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-20210513122809-c18a4d41886e
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
)
