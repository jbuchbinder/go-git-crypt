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
	"log"
	"os"
	"strings"

	"github.com/jbuchbinder/go-git-crypt/gpg"
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

// decryptRepoKey decrypts a repository key, given:
//   - keyring: A GPG keyring to use for the decryption.
//   - keyName: Name of the key set being used. Empty defaults to "default".
//   - keyVersion: Version of the git-crypt keys.
//   - secretKeys: Array of private keys to attempt to decrypt
//   - keysPath: Root path to the repository key directory (should be $REPOPATH/.git-crypt/keys)
func decryptRepoKey(keyring openpgp.EntityList, keyName string, keyVersion uint32, secretKeys []string, keysPath string) (Key, error) {
	//var err error
	keyFile := Key{}

	for _, seckey := range secretKeys {
		path := keysPath + string(os.PathSeparator)
		if keyName == "" {
			path += "default"
		} else {
			path += keyName
		}
		path += string(os.PathSeparator) + fmt.Sprintf("%d", keyVersion) + string(os.PathSeparator) + seckey + ".gpg"

		if fileExists(path) {
			log.Printf("Decrypting key %v in path %s", keyring, path)

			decryptedContents, err := gpgDecryptFromFile(keyring, path)
			if err != nil {
				log.Printf("decryption of file %s : %s", path, err.Error())
				continue
			}
			if len(decryptedContents) == 0 {
				log.Printf("")
				continue
			}

			var thisVersionKeyFile Key
			br := bytes.NewBuffer(decryptedContents)
			err = thisVersionKeyFile.Load(br)
			thisVersionEntry, err := thisVersionKeyFile.Get(keyVersion)
			if err != nil {
				return keyFile, fmt.Errorf("GPG-encrypted keyfile is malformed because it does not contain expected key version")

			}
			if strings.Compare(keyName, thisVersionKeyFile.KeyName) != 0 {
				return keyFile, fmt.Errorf("GPG-encrypted keyfile is malformed because it does not contain expected key name")

			}
			keyFile.Entries = append(keyFile.Entries, thisVersionEntry)
			return keyFile, nil
		}
	}

	return keyFile, errors.New("no secret keys")
}

func decryptRepoKeys(keyring openpgp.EntityList, keyVersion uint32, secretKeys []string, keysPath string) ([]Key, error) {
	successful := false
	dirents := make([]string, 0)
	keyFiles := make([]Key, 0)

	if fileExists(keysPath) {
		fp, err := os.Open(keysPath)
		if err != nil {
			return keyFiles, err
		}
		defer fp.Close()
		entries, err := fp.ReadDir(0)
		if err != nil {
			return keyFiles, err
		}
		for _, entry := range entries {
			dirents = append(dirents, entry.Name())
		}
	}

	for _, dirent := range dirents {
		//log.Printf("decryptRepoKeys : %s", dirent)
		keyName := ""
		if strings.Compare(dirent, "default") != 0 {
			if err := validateKeyName(dirent); err != nil {
				continue
			}
			keyName = dirent
		}

		keyFile, err := decryptRepoKey(keyring, keyName, keyVersion, secretKeys, keysPath)
		if err == nil {
			keyFiles = append(keyFiles, keyFile)
			successful = true
		}
	}
	if !successful {
		return keyFiles, fmt.Errorf("unsuccessful")
	}
	return keyFiles, nil
}

func readFileHeader(filename string) ([]byte, error) {
	header := make([]byte, 10+aesEncryptorNonceLen)
	fp, err := os.Open(filename)
	if err != nil {
		return header, err
	}
	defer fp.Close()
	_, err = fp.Read(header)
	//log.Printf("readFileHeader : read %d bytes : %s", n, header)
	return header, err
}

func decryptStream(keyFile Key, header []byte, in io.Reader, out io.Writer) error {
	//log.Printf("header: %#v", header)
	nonce := header[10:]
	//log.Printf("nonce: %#v", nonce)
	keyVersion := keyFile.Version

	key, err := keyFile.Get(keyVersion)
	if err != nil {
		return fmt.Errorf("git-crypt: error: key version %d not available - please unlock with the latest version of the key", keyVersion)
	}

	aes := NewAesCtrEncryptor(key.AesKey, nonce)
	h := NewHMac(key.HmacKey)
	counter := 0
	for {
		ibuf := make([]byte, 1024)
		obuf := make([]byte, 1024)
		n, err := in.Read(ibuf)
		if err != nil {
			//log.Printf("ERR: %s", err.Error())
			break
		}
		//log.Printf("size = %d, ibuf = %x", n, ibuf)
		err = aes.process(ibuf, obuf, uint32(n))
		if err != nil {
			return err
		}
		//log.Printf("input : %x", string(ibuf))
		//log.Printf("output : %x", string(obuf))

		out.Write(obuf)
		h.Write(obuf)

		counter++
	}

	digest := h.Result()
	//log.Printf("digest = %#v", digest)
	if !leaklessEquals(digest, nonce, aesEncryptorNonceLen) {
		return fmt.Errorf("git-crypt: error: encrypted file has been tampered with")
		// Although we've already written the tampered file to stdout, exiting
		// with a non-zero status will tell git the file has not been filtered,
		// so git will not replace it.
	}

	return nil
}

func gpgDecryptFromFile(keyring openpgp.EntityList, path string) ([]byte, error) {
	filedata, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("gpgDecryptFromFile(%#v, %s): %s", keyring, path, err.Error())
		return []byte{}, err
	}
	out, err := gpg.Decrypt(filedata, keyring)
	if err != nil {
		log.Printf("gpgDecryptFromFile(%#v, %s) : %s", keyring, path, err.Error())
	}
	return out, err
}
