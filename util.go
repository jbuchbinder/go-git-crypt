package gitcrypt

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
)

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func readBigEndianUint32(in io.Reader) (uint32, error) {
	data := make([]byte, 4)
	n, err := in.Read(data)
	if err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, errors.New("unable to read 4 bytes")
	}
	log.Printf("readBigEndianUint32 : %#v", data)
	return uint32(data[0])<<24 + uint32(data[1])<<16 + uint32(data[2])<<8 + uint32(data[3]), nil
}

func storeBigEndian32(p []byte, i uint32) {
	buf := make([]byte, 4)
	buf[3] = byte(i)
	i = i >> 8
	buf[2] = byte(i)
	i = i >> 8
	buf[1] = byte(i)
	i = i >> 8
	buf[0] = byte(i)
	p = append(p, buf...)
}

func writeBigEndianUint32(out io.Writer, val uint32) error {
	data := make([]byte, 4)

	data[0] = byte(val >> 24)
	data[0] = byte(val >> 16)
	data[0] = byte(val >> 8)
	data[0] = byte(val % 256)
	log.Printf("writeBigEndianUint32 : %#v", data)

	n, err := out.Write(data)
	if err != nil {
		return err
	}
	if n != 4 {
		return errors.New("unable to write 4 bytes")
	}
	return nil
}

func readXBytes(in io.Reader, l int) ([]byte, error) {
	b := make([]byte, l)
	n, err := in.Read(b)
	if err != nil {
		return []byte{}, err
	}
	if n != l {
		return b, fmt.Errorf("expected %d bytes, read %d bytes", n, l)
	}
	return b, nil
}

func stringToASCIIBytes(s string) []byte {
	out := make([]byte, 0)
	runes := []rune(s)
	for i := range runes {
		out = append(out, byte(runes[i]))
	}
	return out
}

func randomBytes(length uint32) []byte {
	out := make([]byte, length)
	for i := 0; i < int(length); i++ {
		out[i] = byte(rand.Intn(255))
	}
	return out
}
