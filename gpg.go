package gitcrypt

import (
	"bytes"
	"errors"
	"io/ioutil"
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
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	case openpgp.PrivateKeyType:
		// Handle private key block
		return openpgp.ReadEntity(packet.NewReader(block.Body))
	default:
		return nil, errors.New("ArmoredKeyIngest(): Error ingesting key, unsupported type " + block.Type)
	}
}

func gpgDecrypt(in []byte, secretKeyring openpgp.EntityList) ([]byte, error) {
	// Determine if there's any armoring going on
	if strings.Index(string(in), "BEGIN PGP MESSAGE") != -1 {
		result, err := armor.Decode(bytes.NewReader(in))
		if err != nil {
			return []byte{}, err
		}
		md, err := openpgp.ReadMessage(result.Body, secretKeyring, nil, nil)
		if err != nil {
			return []byte{}, err
		}
		return ioutil.ReadAll(md.UnverifiedBody)
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(in), secretKeyring, nil, nil)
	if err != nil {
		return []byte{}, err
	}
	return ioutil.ReadAll(md.UnverifiedBody)
}
