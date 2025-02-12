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

	"github.com/ProtonMail/go-crypto/openpgp"
	gitcrypt "github.com/jbuchbinder/go-git-crypt"
	"github.com/jbuchbinder/go-git-crypt/gpg"
)

var (
	path   = flag.String("path", "", "Path to repository base")
	gpgkey = flag.String("key", "", "GPG key file")
	debug  = flag.Bool("debug", false, "Debug")
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

	g := gitcrypt.GitCrypt{Debug: *debug}

	keyring := openpgp.EntityList{keydata}
	keysPath := *path + string(os.PathSeparator) + ".git-crypt" + string(os.PathSeparator) + "keys"
	keys, err := g.DecryptRepoKeys(keyring, uint32(0), listKeys(keysPath), keysPath)
	if err != nil {
		panic(err)
	}

	if *debug {
		log.Printf("keys = %#v", keys)
	}

	err = filepath.WalkDir(*path, func(path string, d fs.DirEntry, err error) error {
		if strings.Contains(path, string(os.PathSeparator)+".git") {
			// Skip
			return nil
		}
		if !d.IsDir() {
			if g.IsGitCrypted(path) {
				log.Printf("GIT-CRYPTED: %s", path)
				in, err := os.Open(path)
				if err != nil {
					return err
				}
				defer in.Close()

				header, err := g.ReadFileHeader(in)
				if err != nil {
					return err
				}
				var buf bytes.Buffer
				out := bufio.NewWriter(&buf)

				err = g.DecryptStream(keys[0], header, in, out)
				if err != nil {
					return err
				}
				out.Flush()

				err = os.WriteFile(path+".decrypted", buf.Bytes(), 0600)
				if err != nil {
					log.Printf("ERR: ioutil.WriteFile(%s): %s", path+".decrypted", err.Error())
				}

				err = os.Rename(path+".decrypted", path)
				if err != nil {
					log.Printf("ERR: os.Rename(%s, %s): %s", path+".decrypted", path, err.Error())
				}

				log.Printf("%s: Decrypted %d bytes", path, len(buf.Bytes()))
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
