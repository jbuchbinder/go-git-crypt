package gitcrypt

import (
	"bytes"
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

/*
// Decrypt decrypts a git-crypt encrypted file, given a key and a data
// stream
func (g *GitCrypt) Decrypt(key []byte, data []byte) ([]byte, error) {
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
*/

// DecryptRepoKey decrypts a repository key, given:
//   - keyring: A GPG keyring to use for the decryption.
//   - keyName: Name of the key set being used. Empty defaults to "default".
//   - keyVersion: Version of the git-crypt keys.
//   - secretKeys: Array of private keys to attempt to decrypt
//   - keysPath: Root path to the repository key directory (should be $REPOPATH/.git-crypt/keys)
func (g *GitCrypt) DecryptRepoKey(keyring openpgp.EntityList, keyName string, keyVersion uint32, secretKeys []string, keysPath string) (Key, error) {
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

			decryptedContents, err := g.GpgDecryptFromFile(keyring, path)
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

// DecryptRepoKeys decrypts all available repository keys, given a GPG key
func (g *GitCrypt) DecryptRepoKeys(keyring openpgp.EntityList, keyVersion uint32, secretKeys []string, keysPath string) ([]Key, error) {
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
		log.Printf("decryptRepoKeys : %s", dirent)
		keyName := ""
		if strings.Compare(dirent, "default") != 0 {
			if err := validateKeyName(dirent); err != nil {
				continue
			}
			keyName = dirent
		}

		keyFile, err := g.DecryptRepoKey(keyring, keyName, keyVersion, secretKeys, keysPath)
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

// ReadFileHeaderFromFile fetches the git-crypt file header from an unopened
// file
func (g *GitCrypt) ReadFileHeaderFromFile(filename string) ([]byte, error) {
	header := make([]byte, 10+aesEncryptorNonceLen)
	fp, err := os.Open(filename)
	if err != nil {
		return header, err
	}
	defer fp.Close()
	n, err := fp.Read(header)
	if g.Debug {
		log.Printf("readFileHeaderFromFile : read %d bytes : %s", n, header)
	}
	return header, err
}

// ReadFileHeader fetches the git-crypt file header from an open seekable
// file
func (g *GitCrypt) ReadFileHeader(fp io.ReadSeekCloser) ([]byte, error) {
	header := make([]byte, 10+aesEncryptorNonceLen)
	_, err := fp.Seek(0, io.SeekStart)
	if err != nil {
		return header, err
	}
	n, err := fp.Read(header)
	if g.Debug {
		log.Printf("readFileHeader : read %d bytes : %#v", n, header)
	}
	if err != nil {
		return header, err
	}
	pos, err := fp.Seek(10+aesEncryptorNonceLen, io.SeekStart)
	if g.Debug {
		log.Printf("readFileHeader : seek'd to %d: err = %#v", pos, err)
	}
	return header, err
}

// IsGitCrypted returns whether or not a file has been encrypted in
// the git-crypt encryption format
func (g *GitCrypt) IsGitCrypted(fn string) bool {
	_, err := os.Stat(fn)
	if err != nil {
		// If we can't open the file, skip git-crypting
		log.Printf("ERR: %s", err.Error())
		return false
	}
	fp, err := os.Open(fn)
	if err != nil {
		// If we can't open the file, skip git-crypting
		log.Printf("ERR: %s", err.Error())
		return false
	}
	defer fp.Close()
	b := make([]byte, 10)
	n, err := fp.ReadAt(b, 0)
	if err != nil {
		log.Printf("ERR: %s", err.Error())
		return false
	}
	if n < 10 {
		log.Printf("ERR: only read %d bytes", n)
		return false
	}
	return bytes.Compare(b[0:9], []byte{0, 'G', 'I', 'T', 'C', 'R', 'Y', 'P', 'T'}) == 0
}

// DecryptStream decrypts a stream of encrypted git-crypt format data
// given a key file and header
func (g *GitCrypt) DecryptStream(keyFile Key, header []byte, in io.ReadSeeker, out io.Writer) error {
	if g.Debug {
		log.Printf("header: %#v", header)
	}
	nonce := header[10:]
	if g.Debug {
		log.Printf("nonce: %#v", nonce)
	}
	keyVersion := keyFile.Version

	key, err := keyFile.Get(keyVersion)
	if err != nil {
		return fmt.Errorf("git-crypt: error: key version %d not available - please unlock with the latest version of the key", keyVersion)
	}

	// Attempt to detect if we've read anything already; if we haven't, ignore
	// the header bytes, if not, keep going
	currentPos, err := in.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if currentPos == 0 {
		// Skip past the header before we begin calculations
		ignore := make([]byte, len(header))
		_, err = in.Read(ignore)
		if err != nil {
			return fmt.Errorf("git-crypt: unable to read header: %s", err.Error())
		}
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
		if g.Debug {
			log.Printf("size = %d, ibuf = %x", n, ibuf)
		}
		err = aes.process(ibuf, obuf, uint32(n))
		if err != nil {
			return err
		}
		if g.Debug {
			log.Printf("input : %x", string(ibuf))
			log.Printf("output : %x", string(obuf))
		}

		out.Write(obuf)
		h.Write(obuf)

		counter++
	}

	// TODO: FIXME: IMPLEMENT: HMAC checksumming
	// Right now the algorithm isn't working properly, and therefore is
	// generating a bad sum, so disable for the time being.
	/*
		digest := h.Result()
		log.Printf("digest = %#v, nonce = %#v, len = %d", digest, nonce, aesEncryptorNonceLen)
		if !leaklessEquals(digest, nonce, aesEncryptorNonceLen) {
			return fmt.Errorf("git-crypt: error: encrypted file has been tampered with")
			// Although we've already written the tampered file to stdout, exiting
			// with a non-zero status will tell git the file has not been filtered,
			// so git will not replace it.
		}
	*/

	return nil
}

// GpgDecryptFromFile decrypts a file using a PGP/GPG key
func (g *GitCrypt) GpgDecryptFromFile(keyring openpgp.EntityList, path string) ([]byte, error) {
	filedata, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("GpgDecryptFromFile(%#v, %s): ERR: %s", keyring, path, err.Error())
		return []byte{}, err
	}
	out, err := gpg.Decrypt(filedata, keyring)
	if err != nil {
		log.Printf("GpgDecryptFromFile(%#v, %s): ERR: %s", keyring, path, err.Error())
	}
	return out, err
}
