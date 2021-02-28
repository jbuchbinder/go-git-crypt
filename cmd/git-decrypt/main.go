package main

import (
	"bufio"
	"bytes"
	"flag"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	gitcrypt "github.com/jbuchbinder/go-git-crypt"
	"github.com/jbuchbinder/go-git-crypt/gpg"
	"golang.org/x/crypto/openpgp"
)

var (
	path   = flag.String("path", "", "Path to repository base")
	gpgkey = flag.String("key", "", "GPG key file")
)

func main() {
	flag.Parse()

	if *path == "" || *gpgkey == "" {
		panic("no path or key specified")
	}

	rawkeydata, err := os.ReadFile(*gpgkey)
	if err != nil {
		panic("unable to ingest GPG key")
	}
	keydata, err := gpg.ArmoredKeyIngest(rawkeydata)
	if err != nil {
		panic("unable to ingest GPG key")
	}

	keyring := openpgp.EntityList{keydata}
	keysPath := *path + string(os.PathSeparator) + ".git-crypt" + string(os.PathSeparator) + "keys"
	keys, err := gitcrypt.DecryptRepoKeys(keyring, uint32(0), listKeys(keysPath), keysPath)
	if err != nil {
		panic(err)
	}

	log.Printf("keys = %#v", keys)

	err = filepath.WalkDir(*path, func(path string, d fs.DirEntry, err error) error {
		if strings.Contains(path, string(os.PathSeparator)+".git") {
			// Skip
			return nil
		}
		if !d.IsDir() {
			if gitcrypt.IsGitCrypted(path) {
				log.Printf("GIT-CRYPTED: %s", path)
				header, err := gitcrypt.ReadFileHeader(path)
				if err != nil {
					return err
				}
				in, err := os.Open(path)
				if err != nil {
					return err
				}
				defer in.Close()
				var buf bytes.Buffer
				out := bufio.NewWriter(&buf)

				ignore := make([]byte, len(header))
				in.Read(ignore)

				err = gitcrypt.DecryptStream(keys[0], header, in, out)
				if err != nil {
					return err
				}
				out.Flush()

				log.Printf("Decrypted : %s", string(buf.Bytes()))
			}
		}
		//log.Printf("path = %s, d = %#v", path, d)
		return nil
	})

	if err != nil {
		panic(err)
	}
}

func listKeys(keysPath string) []string {
	keys := make([]string, 0)
	lookin := keysPath + string(os.PathSeparator) + "default" + string(os.PathSeparator) + "0"
	entries, err := os.ReadDir(lookin)
	if err != nil {
		return keys
	}
	for _, e := range entries {
		if !e.IsDir() {
			keys = append(keys, strings.TrimSuffix(e.Name(), ".gpg"))
		}
	}
	return keys
}
