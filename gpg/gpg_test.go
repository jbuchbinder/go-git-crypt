package gpg

import (
	"testing"

	"github.com/bmizerany/assert"
	"golang.org/x/crypto/openpgp"
)

const (
	PUBKEYTEST = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFiKxP8BCACkX7sPYKv3NlctXA95y177ylrPQGJ6b97L2aZ7NCGZ6fE1caiG
tMlOLIzbCBFO4Sx0eir4+uSGrLaGbe5S0KHICpHJaFs1eO1AZ3n9DZ9ILN6HkLDh
zhVPrfTMYO3U/Y+Y/CKdRZ4JT/9TqJrRZ3Mm+4kIY1c9KE6FyvsfWg8beovGwG4X
lFN9xG/QFIVnGrNp/a8GdZ8PstG2j21CgFMMZ8ubGEJPV+yOIBnlsnQrm7MQ/fAF
mfSjeUeDmamAgeyoP1PpkHc48S+FIiDztkFTv7Z/80tsh4eUq+M590FbGz5N/HGH
zhn5e94Qtr4f33BhNiiqa0uS+YDJhPKvVmt9ABEBAAG0H1Rlc3QgR1BHIEtleSA8
dGVzdEBnZXRyYXZlLmNvbT6JATcEEwEIACEFAliKxP8CGwMFCwkIBwIGFQgJCgsC
BBYCAwECHgECF4AACgkQWdPltIb1OTOfeQf8Daqfe/iv8qnzncJU2ORrypPFt/Dx
CJPFVVrBZSGo+YoePnpcsgpOUZ5ou1chUc0IwRu7WBQBnqqw1pfbtsAHovk1Bmrj
hc8O2j9Ar++sk1yRvNZrjDTifiYvPpoDmHSK7RXGqzVArwY6tW1p9gc3yeqyGY5K
NTm93h51Wel8TH/lFwwUSdKVc5TuXtQTbI+FIsEt+iHtBSX0gv+5jQihZRzUicQO
SuEEqR3BGlW/rj8gwPHBFjXn4mQ1TKvYDMMCpzlE06zQXVyaQ0Nw6wcPzbHUitE3
xcKXJw1kABKypkwp00w71nAOOtVgq3nFYtMck+VmSXsy+xS8YlA8hH1LO7kBDQRY
isT/AQgA3pbTBOP1+lxUX0Vox4Q7z8BacB95sSdrojgro2q+/RFPZLF6g3/w228u
B9A/4HoOhax3/f6TN0xELVNKc0WdudT6hBy9tvPjkYYVAnWyPPLEgx+H+d5NiBCM
gbUngLnFE/ghkFHL1sfB8Tfuy28aocTMotTCXi6ZzbFSpEU0eo4o+0zPlHcRkE4D
cSDZtQCZR8EhtTkPwPs6ILLIIT1Rgb4rYz4UubBPzwXRP9MyhJM/tvs+8E2u+Mp+
lsyaGRLMhQfRIXOT3W1iI8Kr3t0Yo6Ff1JRcv/GAN+AmeyBMvGQG7tRer+zA9Oqh
2xcrUmIEvkxoeHlseDCEi4gcymkkMwARAQABiQEfBBgBCAAJBQJYisT/AhsMAAoJ
EFnT5bSG9TkzqboIAJfMNcYcGHElrxcfG1LkcJCDoXrbsL41PIXx6A/q2LLsftm/
BEdjuafqkCCStnm4uhTgulm7qtgd+AHxusM5fdcJgk2ro5GAnJ+0QeIkKYj9BhIY
oUn2dLRBywuangq8h3bkOpMrmgHqZidpyfDOFf+vDnG/UVUNizM1+b5i/sf82jYu
L37vJe/Qcd/hXbBAmzeAyxfakNtQO0qSxFlN8L1BwxV+EglYjeHSP266hI9nKCsL
A9XA49bwcNA7V8eKVD9yC/N4vZ+Yvax1sMRXmXLq/GygY32hDafzPz4/q6qCd7mY
usaU2ATq5LWjNhtbP1PrQivCF12C2e0p48cOGTg=
=bhgK
-----END PGP PUBLIC KEY BLOCK-----
`
	PRIVKEYTEST = `
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=fvlY
-----END PGP PRIVATE KEY BLOCK-----
`
	ENCODEDPAYLOAD = `
-----BEGIN PGP MESSAGE-----

owEBeQGG/pANAwAIAVnT5bSG9TkzAaw3YgtwYXlsb2FkLnR4dFiKxn4wMTIzNDU2
Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaCokBLgQAAQgAGAUCWIrGfhEc
dGVzdEBnZXRyYXZlLmNvbQAKCRBZ0+W0hvU5M1s3B/wLuo0oKVgi6edX7+ubyaDC
4/Is9a+R7KphbfnME1d8aUYwZzXqqrssvjXvYzJmWBQ4F1xxTnyCJmLZXKomYIwz
W5pjVkynVpnLBreu3fj50h9lgpIp+j1wUCT5//FR3K0OzoZuGBcvbr5sOUxAymmM
bnGKyIT9Jag6bIoXmB2Vr6ixJ4oT/XzQUANZasHNBssF56m3pzrNTmg9PY0hMBIj
MucHF7Sncg2j1BnaD5ecba9uaBVzXVyFX4UUe0mbMVFV+nLa72yxWAf0pMre3zz9
GQqPhk9TjDV8Zi3HRLzpNd4kVi0fS6x7rMPNnIXiAd8Lwh62YTbQZIeRKwQ3GAOX
=rJNK
-----END PGP MESSAGE-----
`
	DECODEDPAYLOAD = "01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
)

func TestGpgKeyArmoredDecode(t *testing.T) {
	priv, err := ArmoredKeyIngest([]byte(PRIVKEYTEST))
	if err != nil {
		t.Fatal(err.Error())
	}

	out, err := Decrypt([]byte(ENCODEDPAYLOAD), openpgp.EntityList{priv})
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, string(out), DECODEDPAYLOAD)
}

func TestGpgRoundtrip(t *testing.T) {
	pub, err := ArmoredKeyIngest([]byte(PUBKEYTEST))
	if err != nil {
		t.Fatal(err.Error())
	}
	priv, err := ArmoredKeyIngest([]byte(PRIVKEYTEST))
	if err != nil {
		t.Fatal(err.Error())
	}

	enc, err := Encrypt([]byte(DECODEDPAYLOAD), openpgp.EntityList{pub}, "", "")
	if err != nil {
		t.Fatal(err.Error())
	}
	out, err := Decrypt(enc, openpgp.EntityList{priv})
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, string(out), DECODEDPAYLOAD)
}
