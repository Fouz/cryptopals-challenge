package cryptopals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

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

	// TODO: use generics

	aHex := "1c0111001f010100061a024b53535009181c"
	bHex := "686974207468652062756c6c277320657965"
	expectedHex := "746865206b696420646f6e277420706c6179"

	a, err := HexDecode(aHex)
	if err != nil {
		t.Fatalf("failed to decode hex string a: %v", err)
	}

	b, err := HexDecode(bHex)
	if err != nil {
		t.Fatalf("failed to decode hex string b: %v", err)
	}

	result, err := XOR(a, b)
	if err != nil {
		t.Fatalf("XOR failed: %v", err)
	}

	expected, err := HexDecode(expectedHex)
	if err != nil {
		t.Fatalf("failed to decode expected hex result: %v", err)
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("unexpected XOR result:\n got: %x\nwant: %x", result, expected)
	}
}

func TestProblem3(t *testing.T) {
	frequencyMap := ReadText("http://gutenberg.org/cache/epub/98/pg98.txt")
	for k, v := range frequencyMap {
		t.Logf("%c: , %.5f", k, v)
	}
	encryptedMsg, err := HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatalf("failed to decode hex string a: %v", err)
	}

	res := FindKey(encryptedMsg, frequencyMap)
	decryptedMsg := hex.EncodeToString(res)
	bs, err := hex.DecodeString(decryptedMsg)
	if err != nil {
		panic(err)
	}
	t.Log(string(bs))
}
