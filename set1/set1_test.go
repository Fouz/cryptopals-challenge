package cryptopals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var englishText []byte = ReadText("https://gutenberg.org/cache/epub/98/pg98.txt")
var scoredCharacter map[byte]float64 = ScoreCharacters(englishText)

func TestQ1(t *testing.T) {

	t.Run("it should return an error for invalid hex", func(t *testing.T) {

		// invalid hex contains 'n' exp
		hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6n"
		str, err := DecodeHexToBase64(hexString)
		if err == nil {
			t.Fatalf("This is invalid hex expeted to fail")
		}
		t.Log(str)
	})

	t.Run("it should decode valid hex to correct base64 string", func(t *testing.T) {
		hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		expectedBase64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
		base64String, err := DecodeHexToBase64(hexString)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if base64String != expectedBase64 {
			t.Errorf("unexpected base64 result:\nexpected: %s\ngot:      %s", expectedBase64, base64String)
		}
	})
}

func TestXORHexStrings(t *testing.T) {

	a := DecodeHex(t, "1c0111001f010100061a024b53535009181c")

	b := DecodeHex(t, "686974207468652062756c6c277320657965")

	expected := DecodeHex(t, "746865206b696420646f6e277420706c6179")

	result, err := XOR(a, b)
	if err != nil {
		t.Fatalf("XOR failed: %v", err)
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("unexpected XOR result:\n got: %x\nwant: %x", result, expected)
	}
}

func TestProblem3(t *testing.T) {
	// for k, v := range scoredCharacter {
	// 	t.Logf("%c: , %.5f", k, v)
	// }
	encryptedMsg, err := HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatalf("failed to decode hex string a: %v", err)
	}

	res, _ := FindKey(encryptedMsg, scoredCharacter)
	decryptedMsg := hex.EncodeToString(res)
	bs, err := hex.DecodeString(decryptedMsg)
	if err != nil {
		panic(err)
	}
	t.Log(string(bs))
}

func TestProblem4(t *testing.T) {
	encryptedText := ReadText("https://cryptopals.com/static/challenge-data/4.txt")
	encryptedTextSlice := bytes.Split(encryptedText, []byte("\n"))

	var res []byte
	var lastScore float64

	for _, v := range encryptedTextSlice {
		vHexDcoded, _ := HexDecode(string(v))
		out, score := FindKey(vHexDcoded, scoredCharacter)
		if score > lastScore {
			lastScore = score
			res = out
		}
	}
	t.Log(string(res))
}
func TestProblem5(t *testing.T) {
	txt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	res := RepeatingKeyXOR(txt, key)
	out := hex.EncodeToString(res)

	dec := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if dec != out {
		t.Errorf("Expected: %s\nGot: %s", dec, out)
	}
}

// helpr
func DecodeHex(t *testing.T, s string) []byte {
	result, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex string %s:", s)
	}
	return result
}
