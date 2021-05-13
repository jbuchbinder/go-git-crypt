module github.com/jbuchbinder/go-git-crypt/cmd/git-crypt-add-key

go 1.16

replace (
	github.com/jbuchbinder/go-git-crypt => ../..
	github.com/jbuchbinder/go-git-crypt/gpg => ../../gpg
)

require (
	github.com/jbuchbinder/go-git-crypt v0.0.0-00010101000000-000000000000
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
)
