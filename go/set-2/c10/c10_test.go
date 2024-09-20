package main

import (
	"fmt"
	"testing"
	"encoding/base64"
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
	key := []byte("YELLOW SUBMARINE")

	cipherText := ImplementCBCMode(fileName, key);
	decrypted := DecryptAESCBC(cipherText, key)
	base64Encoded := base64.StdEncoding.EncodeToString(decrypted)
	
	fmt.Println(base64Encoded)
}
