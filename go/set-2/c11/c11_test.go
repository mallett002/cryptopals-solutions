package main

import (
	"fmt"
	"testing"
)

func TestECBAndCBCDetectionOracle(t *testing.T) {
	// Write function to generate random AES key (16 random bytes)
	randomKey := GenerateRandomAESKey(16)
	fmt.Println(len(randomKey))

	// Write function that uses this random key generation and encrypts data with it
	input := "In case I don't see ya, good morning, good afternoon, and good night!"

	cipherText := EncryptionOracle([]byte(input))

	fmt.Println(string(cipherText))
}