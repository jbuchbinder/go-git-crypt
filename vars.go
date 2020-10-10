package gitcrypt

const (
	nonceLength        = 12
	aesBlockLength     = 16
	headerFieldEnd     = 0
	headerFieldKeyName = 1
	keyFieldEnd        = 0
	keyFieldVersion    = 1
	keyFieldAesKey     = 3
	keyFieldHmacKey    = 5
	maxFieldLength     = 1 << 20
	keyNameMaxLength   = 128
	hmacKeyLen         = 64
	aesKeyLen          = 32
	formatVersion      = 2
)
