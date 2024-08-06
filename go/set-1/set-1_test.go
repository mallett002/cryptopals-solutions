package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestC1HexToBase64(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64String := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	result := HexToBase64(hex)

	assert.Equal(t, base64String, result)
}

func TestC2FixedXOR(t *testing.T) {
	source := "1c0111001f010100061a024b53535009181c";
	comparator := "686974207468652062756c6c277320657965";

	result := XORHexStrings(source, comparator);

	assert.Equal(t, "746865206b696420646f6e277420706c6179", result)
}

func TestC3SingleByteXOR(t *testing.T) {
	hexInput := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

	key, _ := GetKeyAndScoreForLine(hexInput);

	assert.Equal(t, 88, key)
}

func TestFindEncryptionKeyInFile(t *testing.T) {
	fileName := "4.txt";

	key := FindEncyptionKeyInFile(fileName);
	assert.Equal(t, 53, key)

	message := FindTextFromFileWithKey(fileName, 53);
	assert.Equal(t, "Now that the party is jumping\n", message)
}

func TestRepeatingKeyXOR(t *testing.T) {
	plainText := `Burning 'em, if you ain't quick and nimble 
I go crazy when I hear a cymbal`;
	expectedEncryptedText := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	encryptedText := RepeatingKeyXOR(plainText);
	assert.Equal(t, expectedEncryptedText, encryptedText)
}