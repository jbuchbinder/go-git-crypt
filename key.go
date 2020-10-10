package gitcrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

// KeyFromFile instantiates a new key from a specified file
func KeyFromFile(filename string) (Key, error) {
	k := Key{}
	err := k.LoadFromFile(filename)
	return k, err
}

// Key is a git-crypt key structure
type Key struct {
	Entries []KeyEntry
	KeyName string
	Debug   bool
}

// LoadFromFile loads a key from a filesystem file
func (k *Key) LoadFromFile(filename string) error {
	if !fileExists(filename) {
		return errors.New("file does not exist")
	}
	fp, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fp.Close()
	return k.Load(fp)
}

// Load imports a key from an io.Reader
func (k *Key) Load(in io.Reader) error {
	preamble, err := readXBytes(in, 16)
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
	err = k.loadHeader(in)
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

// Store stores a copy of the key to a file
func (k Key) Store(out io.Writer) error {
	out.Write([]byte("\x00GITCRYPTKEY"))
	return errors.New("unimplemented") // TODO: XXX: IMPLEMENT
}

// Generate generates a new key
func (k *Key) Generate(version uint32) error {
	return errors.New("unimplemented") // TODO: XXX: IMPLEMENT
}

func (k *Key) loadHeader(in io.Reader) error {
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
				raw, err := readXBytes(in, int(fieldLen))
				k.KeyName = string(raw)
				err = k.validateKeyName(k.KeyName)
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
			_, err := readXBytes(in, int(fieldLen))
			if err != nil {
				return errors.New("malformed")
			}
		}
	}
	return nil
}

func (k Key) validateKeyName(keyName string) error {
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
			raw, err := readXBytes(in, int(fieldLen))
			if err != nil {
				return err
			}
			k.AesKey = raw
		case keyFieldHmacKey:
			if fieldLen != hmacKeyLen {
				return fmt.Errorf("malformed (bad HMAC key)")
			}
			raw, err := readXBytes(in, int(fieldLen))
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
			_, err := readXBytes(in, int(fieldLen))
			if err != nil {
				return err
			}
		}
	}
	return nil
}
