module github.com/jbuchbinder/go-git-crypt

go 1.16

replace github.com/jbuchbinder/go-git-crypt/gpg => ./gpg

require (
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
)
