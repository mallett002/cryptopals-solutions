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