package gitcrypt

import (
	"errors"
	"fmt"
	"io"
	"log"
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
