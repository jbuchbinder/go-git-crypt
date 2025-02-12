package gitcrypt

import (
	"bytes"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
	if strings.Contains(string(in), "BEGIN PGP MESSAGE") {
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
		return io.ReadAll(md.UnverifiedBody)
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(in), secretKeyring, nil, nil)
	if err != nil {
		log.Printf("gpgDecrypt(): ReadMessage: %s", err.Error())
		return []byte{}, err
	}
	return io.ReadAll(md.UnverifiedBody)
}

func gpgEncrypt(in []byte, secretKey *openpgp.Entity) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, openpgp.EntityList{secretKey}, nil, nil, nil)
	if err != nil {
		log.Printf("gpgEncrypt(): Encrypt: %s", err.Error())
		return []byte{}, err
	}
	_, err = w.Write(in)
	if err != nil {
		log.Printf("gpgEncrypt(): Write: %s", err.Error())
		return []byte{}, err
	}
	err = w.Close()
	if err != nil {
		log.Printf("gpgEncrypt(): Close: %s", err.Error())
		return []byte{}, err
	}
	return buf.Bytes(), nil
}
