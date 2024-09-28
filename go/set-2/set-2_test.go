package main

import (
	"testing"
	"fmt"
	"encoding/base64"

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
	key := []byte("YELLOW SUBMARINE")

	cipherText := ImplementCBCMode(fileName, key);
	decrypted := DecryptAESCBC(cipherText, key)
	base64Encoded := base64.StdEncoding.EncodeToString(decrypted)
	
	fmt.Println(base64Encoded)
}

func TestECBAndCBCDetectionOracle(t *testing.T) {
	// Write function to generate random AES key (16 random bytes)
	randomKey := GenerateRandomBytes(16)
	fmt.Println(len(randomKey))

	// Write function that uses this random key generation and encrypts data with it
	input := "In case I don't see ya, good afternoon, good evening, and good night!"

	cipherText, key, mode := EncryptionOracle([]byte(input))
	plainText := DecryptionOracle(cipherText, key, mode)

	fmt.Printf("mode: %v\n", mode)
	fmt.Printf("cipherText: %v\n", string(cipherText))
	fmt.Printf("plainText: %v\n", string(plainText))
}

func TestByteAtATimeECBDecryptionSimple(t *testing.T) {
	input := "In case I don't see ya, good afternoon, good evening, and good night!"

	cipherText := EncryptEcbBuffers([]byte(input))
	fmt.Println(string(cipherText))

	// Left off at https://cryptopals.com/sets/2/challenges/12: "Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents."
}