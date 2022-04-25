package gitcrypt

const (
	nonceLength               = 12
	aesBlockLength            = 16
	headerFieldEnd            = 0
	headerFieldKeyName        = 1
	keyFieldEnd               = 0
	keyFieldVersion           = 1
	keyFieldAesKey            = 3
	keyFieldHmacKey           = 5
	maxFieldLength            = 1 << 20
	keyNameMaxLength          = 128
	hmacKeyLen                = 64
	aesKeyLen                 = 32
	formatVersion             = 2
	aesEncryptorNonceLen      = 12
	aesEncryptorKeyLen        = aesKeyLen
	aesEncryptorBlockLen      = 16
	aesEncryptorMaxCryptBytes = (1 << 32) * 16 // Don't encrypt more than this or the CTR value will repeat itself
)

var (
	// gitCryptHeader is the constant header which is present in all
	// git-crypted files
	gitCryptHeader = []byte{0, 'G', 'I', 'T', 'C', 'R', 'Y', 'P', 'T'}
)
