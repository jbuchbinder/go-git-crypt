package gitcrypt

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

// HMac represents an HMAC encryptor/decryptor
type HMac struct {
	hmacHash hash.Hash
}

// NewHMac creates an HMac encryptor/decryptor
func NewHMac(key []byte) HMac {
	h := HMac{
		hmacHash: hmac.New(sha1.New, key),
	}
	return h
}

// Write adds bytes to the HMAC hash
func (h *HMac) Write(w []byte) {
	h.hmacHash.Write(w)
}

// Result returns the resultant sum
func (h *HMac) Result() []byte {
	return h.hmacHash.Sum(nil)
}
