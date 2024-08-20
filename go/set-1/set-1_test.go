package main

import (
	"testing"
	"fmt"

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
	// https://cryptopals.com/sets/1/challenges/5
	plainText := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	expectedEncryptedText := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
	key := "ICE"

	encryptedText := RepeatingKeyXOR(plainText, key);
 
	assert.Equal(t, expectedEncryptedText, encryptedText)
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	/* 1. Find the key
	    - KEYSIZE: guessed length of the key
	    - write function to compute Hamming distance btw 2 strings (number of differing bits) 
       */
	// Hamming distance
	assert.Equal(t, 37, GetHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))

	key := BreakRepeatingKeyXOR("6.txt");
 
	assert.Equal(t, "fooey", key)
}

func TestTransposeBlocks(t *testing.T) {
	str := "hello world"
	bites := []byte(str) 
	
	// [104 101 108, 108 111 32, 119 111 114, 108 100]
	// [hel, lo_, wor, ld]
	expected := [][]byte{
		{104, 108, 119, 108},
		{101, 111, 111, 100},
		{108, 32, 114},
	}

	result := TransposeBlocks(bites, 3)

	fmt.Printf("expected: %v/\n", expected)
	fmt.Printf("result: %v/\n", result)

	assert.Equal(t, expected, result)
}