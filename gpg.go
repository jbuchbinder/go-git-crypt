package gitcrypt

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type rawKeyData []byte

func gpgArmoredKeyIngest(input rawKeyData) (*openpgp.Entity, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case openpgp.PublicKeyType:
		// Handle public key block
		log.Printf("gpgArmoredKeyIngest(): ingesting public key")
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	case openpgp.PrivateKeyType:
		// Handle private key block
		log.Printf("gpgArmoredKeyIngest(): ingesting private key")
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	default:
		return nil, errors.New("gpgArmoredKeyIngest(): Error ingesting key, unsupported type " + block.Type)
	}
}

func gpgDecrypt(in []byte, secretKeyring openpgp.EntityList) ([]byte, error) {
	// Determine if there's any armoring going on
	if strings.Index(string(in), "BEGIN PGP MESSAGE") != -1 {
		result, err := armor.Decode(bytes.NewReader(in))
		if err != nil {
			log.Printf("gpgDecrypt(): Decode(armored): %s", err.Error())
			return []byte{}, err
		}
		md, err := openpgp.ReadMessage(result.Body, secretKeyring, nil, nil)
		if err != nil {
			log.Printf("gpgDecrypt(): ReadMessage(armored): %s", err.Error())
			return []byte{}, err
		}
		return ioutil.ReadAll(md.UnverifiedBody)
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(in), secretKeyring, nil, nil)
	if err != nil {
		log.Printf("gpgDecrypt(): ReadMessage: %s", err.Error())
		return []byte{}, err
	}
	return ioutil.ReadAll(md.UnverifiedBody)
}
