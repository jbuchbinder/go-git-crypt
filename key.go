package gitcrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
)

// Key is a git-crypt key structure
type Key struct {
	Entries []KeyEntry
	KeyName string
	Debug   bool
}

// Load imports a key from an io.Reader
func (k *Key) Load(in io.Reader) error {
	preamble := make([]byte, 16)
	_, err := in.Read(preamble)
	if err != nil {
		return err
	}
	if preamble[0] != byte(0) && bytes.Compare(preamble[1:13], []byte("GITCRYPTKEY")) != 0 {
		return fmt.Errorf("malformed preamble")
	}
	format, err := readBigEndianUint32(bytes.NewBuffer(preamble[12:]))
	if err != nil {
		return err
	}
	if format != formatVersion {
		return fmt.Errorf("uncompatible version %d", format)
	}
	if k.Debug {
		log.Printf("format: %d", format)
	}
	err = k.LoadHeader(in)
	if err != nil {
		return fmt.Errorf("LoadHeader: %s", err.Error())
	}
	k.Entries = make([]KeyEntry, 0)
	for {
		entry := KeyEntry{}
		err = entry.Load(in)
		if err != nil {
			break
		}
		k.Entries = append(k.Entries, entry)
	}

	return nil
}

func (k *Key) LoadHeader(in io.Reader) error {
	for {
		fieldID, err := readBigEndianUint32(in)
		if err != nil {
			return errors.New("malformed")
		}
		if fieldID == headerFieldEnd {
			break
		}
		fieldLen, err := readBigEndianUint32(in)
		if err != nil {
			return errors.New("malformed")
		}

		switch fieldID {
		case headerFieldKeyName:
			if fieldLen > keyNameMaxLength {
				return errors.New("malformed")
			}
			if fieldLen == 0 {
				// special case field_len==0 to avoid possible undefined behavior
				// edge cases with an empty std::vector (particularly, &bytes[0]).
				k.KeyName = ""
			} else {
				raw := make([]byte, fieldLen)
				_, err := in.Read(raw)
				k.KeyName = string(raw)
				err = k.ValidateKeyName(k.KeyName)
				if err != nil {
					k.KeyName = ""
					return errors.New("malformed")
				}
			}
		case fieldID & 1:
			return errors.New("incompatible")
		default:
			// unknown non-critical field - safe to ignore
			if fieldLen > maxFieldLength {
				return errors.New("malformed")
			}
			ignore := make([]byte, fieldLen)
			_, err := in.Read(ignore)
			if err != nil {
				return errors.New("malformed")
			}
		}
	}
	return nil
}

func (k Key) ValidateKeyName(keyName string) error {
	if keyName == "" {
		return errors.New("key name may not be empty")
	}

	if keyName == "default" {
		return errors.New("`default' is not a legal key name")
	}
	// Need to be restrictive with key names because they're used as part of a Git filter name
	for i := 0; i < len(keyName); i++ {
		ch := byte(keyName[i])
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch == '-' || ch == '_' {
			continue
		}
		return errors.New("Key names may contain only A-Z, a-z, 0-9, '-', and '_'")
	}

	if len(keyName) > keyNameMaxLength {
		return errors.New("key name is too long")
	}
	return nil
}

// KeyEntry is a key entry
type KeyEntry struct {
	Version uint32
	AesKey  []byte
	HmacKey []byte
}

// Load loads an entry from a stream
func (k *KeyEntry) Load(in io.Reader) error {
	for {
		fieldID, err := readBigEndianUint32(in)
		if err != nil {
			return errors.New("malformed")
		}
		if fieldID == keyFieldEnd {
			break
		}
		fieldLen, err := readBigEndianUint32(in)
		if err != nil {
			return errors.New("malformed")
		}
		switch fieldID {
		case keyFieldVersion:
			if fieldLen != 4 {
				return fmt.Errorf("malformed version")
			}
			k.Version, err = readBigEndianUint32(in)
			if err != nil {
				return err
			}
		case keyFieldAesKey:
			if fieldLen != aesKeyLen {
				return fmt.Errorf("malformed (bad AES key)")
			}
			raw := make([]byte, fieldLen)
			_, err := in.Read(raw)
			if err != nil {
				return err
			}
			k.AesKey = raw
		case keyFieldHmacKey:
			if fieldLen != hmacKeyLen {
				return fmt.Errorf("malformed (bad HMAC key)")
			}
			raw := make([]byte, fieldLen)
			_, err := in.Read(raw)
			if err != nil {
				return err
			}
			k.HmacKey = raw
		case fieldID & 1:
			return fmt.Errorf("malformed")
		default:
			if fieldLen > maxFieldLength {
				return fmt.Errorf("malformed (> maxFieldLength)")
			}
			ignore := make([]byte, fieldLen)
			_, err := in.Read(ignore)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
