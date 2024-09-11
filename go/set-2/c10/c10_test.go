package main

import (
	"fmt"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestImplementCBCMode(t *testing.T) {
	/*
		- CBC - block cipher that encrypts irregularly sized messages
		- each ciphertext block added to next plaintext block before applying cipher
		- the first plaintext block that has no previous ciphertext block gets added a fake 0th ciphertext block called the init vector (IV)
		- Implement:
			- Take ECB func & make it encrypt instead of decrypt (DecryptFileAESinECBmode)
				- verify by decrypting what you encrypt
			- Use XOR function from previous exercise to combine them ()
			- CBC decrypt "10.txt" against "YELLOW SUBMARINE" with IV of all ASCII 0 (\x00\x00\x00 &c)
	*/

	/*
		Adapt DecryptFileAESinECBmode func to encrypt data in ECB mode.
		use the ECB encryption func with XOR and chaining mechanism of CBC
		- Use ECB func to encrypt
		- But before each encryption, XOR the plaintext block with the previous ciphertext block (starting with IV for first block)	
	*/
	fileName := "10.txt"
	key := "YELLOW SUBMARINE"

	cipherText := ImplementCBCMode(fileName, key);

	fmt.Println(cipherText)

	assert.Equal(t, "YELLOW SUBMARINE\x04\x04\x04\x04", cipherText)
}
 