package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
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

// Q3
func ReadText(url string) []byte {

	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return body
}

// func ReadText(fileName string) []byte {
// 	text, err := os.ReadFile(fileName)
// 	if err != nil {
// 		fmt.Errorf("failed to open file: %w", err)
// 	}
// 	return text
// }

func ScoreCharacters(text []byte) map[byte]float64 {

	frequencyMap := make(map[byte]float64)

	totalCount := float64(len(text))

	for _, val := range text {
		frequencyMap[val]++
	}

	for key, val := range frequencyMap {
		frequencyMap[key] = val / totalCount
	}

	return frequencyMap
}

func Score(b []byte, f map[byte]float64) float64 {
	var score float64
	for _, val := range b {
		score += f[val]
	}
	return score / float64(len(b))
}

func SingleByteXOR(b []byte, key byte) []byte {

	fullKey := bytes.Repeat([]byte{key}, len(b))
	res, _ := XOR(fullKey, b)
	return res

}

func FindKey(e []byte, f map[byte]float64) ([]byte, float64) {
	var res []byte
	var lastScore float64

	for key := byte(0); key <= 255; key++ {
		out := SingleByteXOR(e, key)
		score := Score(out, f)
		if score > lastScore {
			res = out
			lastScore = score
		}
		// for future me: the loop would (byte overflow) after 255 and reset to 0 causing an infinite loop.
		if key == 255 {
			break
		}
	}
	return res, lastScore
}

// Problem #5

func RepeatingKeyXOR(m []byte, key []byte) []byte {
	res := make([]byte, len(m))
	c := 0
	for i, v := range m {
		if c > 2 {
			c = 0
		}
		res[i] = v ^ key[c]
		c = c + 1
	}
	return res
}
