module github.com/jbuchbinder/go-git-crypt

go 1.16

replace github.com/jbuchbinder/go-git-crypt/gpg => ./gpg

require (
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-20220425133450-dab346ecc2c3
	golang.org/x/crypto v0.9.0
	golang.org/x/tools v0.9.1
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
