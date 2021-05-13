package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	gitcrypt "github.com/jbuchbinder/go-git-crypt"
	"github.com/jbuchbinder/go-git-crypt/gpg"
	"golang.org/x/crypto/openpgp"
)

var (
	path   = flag.String("path", "", "Path to repository base")
	gpgkey = flag.String("key", "", "GPG key file")
	addkey = flag.String("addkey", "", "GPG public key file to add")
	debug  = flag.Bool("debug", false, "Debug")
)

func main() {
	flag.Parse()

	if *path == "" || *gpgkey == "" || *addkey == "" {
		panic("no path, key, or addkey specified")
	}

	var keydata *openpgp.Entity
	var newkeydata *openpgp.Entity

	{
		rawkeydata, err := os.ReadFile(*gpgkey)
		if err != nil {
			panic("unable to ingest GPG key")
		}
		keydata, err = gpg.ArmoredKeyIngest(rawkeydata)
		if err != nil {
			panic("unable to ingest GPG key")
		}
	}

	{
		rawkeydata, err := os.ReadFile(*addkey)
		if err != nil {
			panic("unable to ingest public GPG key")
		}
		newkeydata, err = gpg.ArmoredKeyIngest(rawkeydata)
		if err != nil {
			panic("unable to ingest public GPG key")
		}
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

	buf := make([]byte, 0)
	plainOut := bytes.NewBuffer(buf)
	err = keys[0].Store(plainOut)
	if err != nil {
		panic(err)
	}

	out, err := gpg.Encrypt(plainOut.Bytes(), openpgp.EntityList{newkeydata}, "", "")
	if err != nil {
		panic(err)
	}

	outfilename := keysPath + string(os.PathSeparator) + "default" + string(os.PathSeparator) + "0" +
		string(os.PathSeparator) + gpg.Fingerprint(newkeydata) + ".gpg"
	if *debug {
		log.Printf("outfilename = %s", outfilename)
	}
	err = ioutil.WriteFile(outfilename, out, 0600)
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
