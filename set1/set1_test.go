package cryptopals

import (
	"bytes"
	"testing"
)

func TestQ1(t *testing.T) {

	t.Run("it should return an error for invalid hex", func(t *testing.T) {

		// invalid hex contains 'n' exp
		hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6n"
		_, err := DecodeHexToBase64(hexString)
		if err == nil {
			t.Fatalf("This is invalid hex expeted to fail")
		}
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
