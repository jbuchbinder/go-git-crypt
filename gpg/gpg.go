package gpg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Decrypt decrypts an input byte array with keys in secretkeyring
func Decrypt(in []byte, secretKeyring openpgp.EntityList) ([]byte, error) {
	log.Printf("gpg.Decrypt(%d bytes)", len(in))

	// Determine if there's any armoring going on
	if strings.Contains(string(in), "BEGIN PGP MESSAGE") {
		log.Printf("gpg.Decrypt(): Found armored message data")
		result, err := armor.Decode(bytes.NewReader(in))
		if err != nil {
			return []byte{}, err
		}
		md, err := openpgp.ReadMessage(result.Body, secretKeyring, nil, nil)
		if err != nil {
			return []byte{}, err
		}
		return io.ReadAll(md.UnverifiedBody)
	}

	log.Printf("gpg.Decrypt(): Processing raw data")
	md, err := openpgp.ReadMessage(bytes.NewReader(in), secretKeyring, nil, nil)
	if err != nil {
		return []byte{}, err
	}
	return io.ReadAll(md.UnverifiedBody)
}

// Encrypt encrypts an input byte array using an opengpg.EntityList
// and a specific key identifier. It can optionally read a file containing
// keys if specified in masterKeyFilePath. It returns encrypted data
// or an error if one is encountered.
func Encrypt(in []byte, publicKeyring openpgp.EntityList, id string, masterKeyFilePath string) ([]byte, error) {
	log.Printf("gpg.Encrypt(%d bytes, key %s)", len(in), id)

	myID := id
	if myID == "" && len(publicKeyring) > 0 {
		myID = EntityID(publicKeyring[0])
		log.Printf("gpg.Encrypt(): Autodetected entity id %s", myID)
	}

	key := getKeyByID(publicKeyring, myID)
	if key == nil {
		return []byte{}, errors.New("gpg.Encrypt(): Unable to locate key " + myID)
	}

	var el openpgp.EntityList
	if masterKeyFilePath == "" || !fileExists(masterKeyFilePath) {
		// Just use the extracted db key
		el = openpgp.EntityList{key}
	} else {
		// Attach the master key to it so that we can decrypt
		masterkeyfile, err := os.ReadFile(masterKeyFilePath)
		if err != nil {
			log.Printf("gpg.Encrypt(): Unable to ingest master GPG key: %s", err.Error())
			el = openpgp.EntityList{key}
		} else {
			masterkey, err := ArmoredKeyIngest([]byte(masterkeyfile))
			if err != nil {
				log.Printf("gpg.Encrypt(): Unable to ingest master GPG key: %s", err.Error())
				el = openpgp.EntityList{key}
			} else {
				log.Printf("gpg.Encrypt(): Encrypting data with key %s and master key", EntityID(key))
				el = openpgp.EntityList{key, masterkey}
			}
		}
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, el, nil, nil, nil)
	if err != nil {
		return []byte{}, err
	}
	_, err = w.Write(in)
	if err != nil {
		return []byte{}, err
	}
	err = w.Close()
	if err != nil {
		return []byte{}, err
	}
	log.Printf("Encrypt(): Outputting %d bytes", len(buf.Bytes()))
	return io.ReadAll(buf)
}

// RawKeyData is a convenience type for []byte, used for ingesting raw GPG
// key data.
type RawKeyData []byte

// ArmoredKeyIngest extracts a single entity, public or private, from an array
// of bytes. Theoretically we could use openpgp's ReadArmoredKeyRing, but we
// can't really build our own keyring that way, and we're storing these keys
// in separate database records.
func ArmoredKeyIngest(input RawKeyData) (*openpgp.Entity, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case openpgp.PublicKeyType:
		// Handle public key block
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	case openpgp.PrivateKeyType:
		// Handle private key block
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	default:
		return nil, errors.New("gpg.ArmoredKeyIngest(): Error ingesting key, unsupported type " + block.Type)
	}
}

// KeyArrayToEntityList converts an array of armored GPG key data into an
// opengpg.EntityList, throwing errors if no keys are found or errors are
// encountered during the ingest process.
func KeyArrayToEntityList(ka []RawKeyData) (openpgp.EntityList, error) {
	el := make([]*openpgp.Entity, 0)
	for _, k := range ka {
		e, err := ArmoredKeyIngest(k)
		if err != nil {
			log.Printf("gpg.KeyArrayToEntityList(): %s", err.Error())
			continue
		}
		el = append(el, e)
	}
	if len(el) < 1 {
		return openpgp.EntityList(el), errors.New("gpg.KeyArrayToEntityList(): No keys found")
	}
	return openpgp.EntityList(el), nil
}

// EntityID extracts the short name string for the ID for an entity.
func EntityID(e *openpgp.Entity) string {
	return e.PrimaryKey.KeyIdShortString()
}

// Fingerprint returns the 40-byte fingerprint name associated with an entity
func Fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
}

func getKeyByID(keyring openpgp.EntityList, id string) *openpgp.Entity {
	for _, entity := range keyring {
		if EntityID(entity) == id {
			return entity
		}
	}
	return nil
}
