package main

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestPksNumber7(t *testing.T) {
	/*
		- Block cipher encrypts a fixed size block of plaintext (usually 8 to 16 bytes) into ciphertext
		- We usually encryt irregular sizes, and not fixed size blocks though
		- To fix this, we create regular sized blocks by adding padding, such as PKCS#7
		- Pad blocks to specific block length by adding the number of desired bytes of padding
			- Ex: "YELLOW SUBMARINE" padded to 20 bytes would be "YELLOW SUBMARINE\x04\x04\x04\x04"
	*/
	plainText := "YELLOW SUBMARINE";

	withPadding := PKSNumber7(plainText, 20);

	assert.Equal(t, "YELLOW SUBMARINE\x04\x04\x04\x04", withPadding)
}
 