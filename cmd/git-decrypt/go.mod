module github.com/jbuchbinder/go-git-crypt/cmd/git-decrypt

go 1.21

replace (
	github.com/jbuchbinder/go-git-crypt => ../..
	github.com/jbuchbinder/go-git-crypt/gpg => ../../gpg
)

require (
	github.com/jbuchbinder/go-git-crypt v0.0.0-20230531185652-a4bc6e5f7bd6
	github.com/jbuchbinder/go-git-crypt/gpg v0.0.0-20230531185652-a4bc6e5f7bd6
	golang.org/x/crypto v0.18.0
)

require (
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
)
