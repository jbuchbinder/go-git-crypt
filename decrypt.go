package gitcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Decrypt decrypts a git-crypt encrypted file, given a key and a data
// stream
func Decrypt(key []byte, data []byte) ([]byte, error) {
	var out []byte
	block, err := aes.NewCipher(key)
	if err != nil {
		return out, err
	}

	h := hmac.New(sha1.New, key)

	block.Decrypt(data, out)
	_, err = h.Write(out)
	if err != nil {
		return out, err
	}

	return out, nil
}

func decryptRepoKey(gpgkey openpgp.Entity, keyFile Key, keyName string, keyVersion uint32, secretKeys []string, keysPath string) error {
	//var err error

	for _, seckey := range secretKeys {
		path := keysPath + string(os.PathSeparator)
		if keyName == "" {
			path += "default"
		} else {
			path += keyName
		}
		path += string(os.PathSeparator) + fmt.Sprintf("%d", keyVersion) + string(os.PathSeparator) + seckey + ".gpg"

		if fileExists(path) {
			decryptedContents, err := gpgDecryptFromFile(gpgkey, path)
			if err != nil {
				return err
			}
			if len(decryptedContents) > 0 {

			}

			var thisVersionKeyFile Key
			br := bytes.NewBuffer(decryptedContents)
			err = thisVersionKeyFile.Load(br)
			thisVersionEntry, err := thisVersionKeyFile.Get(keyVersion)
			if err != nil {
				return fmt.Errorf("GPG-encrypted keyfile is malformed because it does not contain expected key version")

			}
			if strings.Compare(keyName, thisVersionKeyFile.KeyName) != 0 {
				return fmt.Errorf("GPG-encrypted keyfile is malformed because it does not contain expected key name")

			}
			keyFile.Entries = append(keyFile.Entries, thisVersionEntry)
			return nil
		}
	}

	return errors.New("no secret keys")
}

func decryptRepoKeys(gpgkey openpgp.Entity, keyFiles []Key, keyVersion uint32, secretKeys []string, keysPath string) error {
	successful := false
	dirents := make([]string, 0)

	if fileExists(keysPath) {
		fp, err := os.Open(keysPath)
		if err != nil {
			return err
		}
		defer fp.Close()
		entries, err := fp.ReadDir(0)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			dirents = append(dirents, entry.Name())
		}
	}

	for _, dirent := range dirents {
		keyName := ""
		if strings.Compare(dirent, "default") != 0 {
			if err := validateKeyName(dirent); err != nil {
				continue
			}
			keyName = dirent
		}

		var keyFile Key
		if err := decryptRepoKey(gpgkey, keyFile, keyName, keyVersion, secretKeys, keysPath); err == nil {
			keyFiles = append(keyFiles, keyFile)
			successful = true
		}
	}
	if !successful {
		return fmt.Errorf("unsuccessful")
	}
	return nil
}

func decryptFileToStdout(keyFile Key, header []byte, in io.Reader) error {
	nonce := header[:10]
	var keyVersion uint32 = 0 // TODO: get the version from the file header

	key, err := keyFile.Get(keyVersion)
	if err != nil {
		return fmt.Errorf("git-crypt: error: key version %d not available - please unlock with the latest version of the key", keyVersion)
	}

	aes := NewAesCtrEncryptor(key.AesKey, nonce)
	//Hmac_sha1_state         hmac(key->hmac_key, HMAC_KEY_LEN);
	for {
		ibuf := make([]byte, 1024)
		obuf := make([]byte, 1024)
		n, err := in.Read(ibuf)
		if err != nil {
			break
		}
		err = aes.process(ibuf, obuf, uint32(n))
		if err != nil {
			return err
		}
		//hmac.add(buffer, in.gcount());
		fmt.Printf("%s", string(obuf))
	}

	//unsigned char           digest[Hmac_sha1_state::LEN];
	//digest := make([]byte, hmacSha1StateLen)
	//hmac.get(digest);
	//if (!leakless_equals(digest, nonce, Aes_ctr_decryptor::NONCE_LEN)) {
	//return fmt.Errorf("git-crypt: error: encrypted file has been tampered with!")
	// Although we've already written the tampered file to stdout, exiting
	// with a non-zero status will tell git the file has not been filtered,
	// so git will not replace it.
	//}

	return nil
}

func gpgDecryptFromFile(gpgkey openpgp.Entity, path string) ([]byte, error) {
	filedata, err := ioutil.ReadFile(path)
	if err != nil {
		return []byte{}, err
	}
	out, err := gpgDecrypt(filedata, openpgp.EntityList{&gpgkey})
	return out, err
}
