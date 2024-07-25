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

	key := FindEncyptionKey(hexInput);

	assert.Equal(t, 88, key)
}