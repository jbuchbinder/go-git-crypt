package gitcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

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

func decryptRepoKey(gpgkey openpgp.Entity, keyFile []string, keyName string, keyVersion uint32, secretKeys []string, keysPath string) error {
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
			//thisVersionEntry := thisVersionKeyFile.
			/*
				                        const Key_file::Entry*  this_version_entry = this_version_key_file.get(key_version);
				                        if (!this_version_entry) {
				                                throw Error("GPG-encrypted keyfile is malformed because it does not contain expected key version");
				                        }
				                        if (!same_key_name(key_name, this_version_key_file.get_key_name())) {
				                                throw Error("GPG-encrypted keyfile is malformed because it does not contain expected key name");
				                        }
				                        key_file.set_key_name(key_name);
										key_file.add(*this_version_entry);
			*/
			return nil
		}
	}

	return errors.New("no secret keys")
}

func gpgDecryptFromFile(gpgkey openpgp.Entity, path string) ([]byte, error) {
	filedata, err := ioutil.ReadFile(path)
	if err != nil {
		return []byte{}, err
	}
	out, err := gpgDecrypt(filedata, openpgp.EntityList{&gpgkey})
	return out, err
}
