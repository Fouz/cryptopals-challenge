package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Q1
func DecodeHexToBase64(hs string) (string, error) {

	src, err := HexDecode(hs)
	if err != nil {
		return "", err
	}

	base64String := base64.StdEncoding.EncodeToString(src)
	return base64String, nil

}

func HexDecode(hs string) ([]byte, error) {

	res, err := hex.DecodeString(hs)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Q2
func XOR(b1, b2 []byte) ([]byte, error) {

	if len(b1) != len(b2) {
		return nil, fmt.Errorf("input length mismatch")
	}

	res := make([]byte, len(b1))

	for i, _ := range res {
		res[i] = b1[i] ^ b2[i]
	}

	return res, nil
}
