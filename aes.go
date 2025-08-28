package gitcrypt

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

// AesCtrEncryptor represents an AES encryptor/decryptor
type AesCtrEncryptor struct {
	// Debug represents whether debug logging is turned on or not
	Debug bool

	ctrValue    []byte // Current CTR value (used as input to AES to derive pad)
	pad         []byte // Current encryption pad (output of AES)
	byteCounter uint32 // How many bytes processed so far?
	key         []byte
}

// NewAesCtrEncryptor creates a new AesCtrEncryptor instance with a key and nonce
func NewAesCtrEncryptor(rawKey []byte, nonce []byte) AesCtrEncryptor {
	obj := AesCtrEncryptor{}
	obj.ctrValue = make([]byte, aesEncryptorBlockLen)
	obj.pad = make([]byte, aesEncryptorBlockLen)
	obj.key = rawKey
	// Set first 12 bytes of the CTR value to the nonce.
	// This stays the same for the entirety of this object's lifetime.
	for i := 0; i < nonceLength; i++ {
		obj.ctrValue[i] = nonce[i]
	}
	obj.byteCounter = 0
	return obj
}

// TODO: Deal with implementing destructor
/*
Aes_ctr_encryptor::~Aes_ctr_encryptor ()
{
        explicit_memset(pad, '\0', BLOCK_LEN);
}
*/

func (a *AesCtrEncryptor) process(in []byte, out []byte, len uint32) error {
	var i uint32
	//log.Printf("process for length = %d", len)
	for i = 0; i < len; i++ {
		if a.byteCounter%aesEncryptorBlockLen == 0 {
			//log.Printf("a.byteCounter = %d, aesEncryptorBlockLen = %d", a.byteCounter, aesEncryptorBlockLen)
			// Set last 4 bytes of CTR to the (big-endian) block number (sequentially increasing with each block)
			tmp := make([]byte, 4)
			binary.BigEndian.PutUint32(tmp, a.byteCounter/aesEncryptorBlockLen)
			if a.Debug {
				log.Printf("tmp = %#v, bytecounter = %d, blockLen = %d", tmp, a.byteCounter, aesEncryptorBlockLen)
			}
			//store_be32(ctr_value + NONCE_LEN, byte_counter / BLOCK_LEN)
			if a.Debug {
				log.Printf("last four bytes of CTR : %x", tmp)
			}
			for i := range 4 {
				a.ctrValue[aesEncryptorNonceLen+i] = tmp[i]
			}
			//log.Printf("ctrValue = %#v", a.ctrValue)

			// Generate a new pad
			c, err := aes.NewCipher(a.key)
			if err != nil {
				return err
			}
			c.Encrypt(a.pad, a.ctrValue)

			//log.Printf("pad = %x", a.pad)
		}

		// encrypt one byte
		out[i] = in[i] ^ a.pad[a.byteCounter%aesEncryptorBlockLen]
		a.byteCounter++
		//log.Printf("pos %d, in = %x, out = %x, pad = %x", i, in[i], out[i], a.pad[a.byteCounter%aesEncryptorBlockLen])

		if a.byteCounter == 0 {
			return fmt.Errorf("aes_ctr_encryptor::process - Too much data to encrypt securely")
		}
	}
	return nil
}

// Encrypt/decrypt an entire input stream, writing to the given output stream
func (a *AesCtrEncryptor) processStream(in io.Reader, out io.Writer, key []byte, nonce []byte) error {
	c := NewAesCtrEncryptor(key, nonce)
	if len(c.key) == 0 {
		return fmt.Errorf("bad key")
	}
	ibuf := make([]byte, 1024)
	obuf := make([]byte, 1024)
	for {
		n, err := in.Read(ibuf)
		if err != nil {
			break
		}
		err = c.process(ibuf, obuf, uint32(n))
		if err != nil {
			return err
		}
		_, err = out.Write(obuf)
		if err != nil {
			return err
		}
	}
	return nil
}
