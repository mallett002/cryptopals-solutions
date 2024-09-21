package main

import (
	"fmt"
	"log"
	"crypto/rand"
	"math/big"
)

func GenerateRandomBytes(byteLength int) []byte {
	token := make([]byte, byteLength)

	_, err := rand.Read(token)
	if err != nil {
		log.Fatalf("error generating random key: %v", err)
	}

	return token
}

func GenerateRandomInt(min int64, max int64) int {
	minBig := big.NewInt(min)
	maxBig := big.NewInt(max)

	diff := big.NewInt(0).Sub(maxBig, minBig)
	diffPlusOne := big.NewInt(0).Add(diff, big.NewInt(1))

	nBig, err := rand.Int(rand.Reader, diffPlusOne)
	if err != nil {
		log.Fatalf("error generating random number: %v", err)
	}

	n := big.NewInt(0).Add(nBig, minBig).Int64()

	return int(n)
}

// Appends 5-10 random bytes before plaintext and 5-10 bytes after plaintext
// Encrypts ECB 1/2 the time and CBC other half - rand(2) each time to decide
// 	- uses random IVs each time for CBC
// Detects which mode (ECB || CBC) used
func EncryptionOracle(plaintext []byte) []byte {
	randomKey := GenerateRandomBytes(16)	
	prevText := GenerateRandomBytes(GenerateRandomInt(5, 10))
	postText := GenerateRandomBytes(GenerateRandomInt(5, 10))


	newPlaintext := append(prevText, plaintext...)
	newPlaintext = append(newPlaintext, postText...)

	fmt.Printf("prevText: %v\n", prevText)
	fmt.Printf("postText: %v\n", postText)
	fmt.Printf("newPlaintext: %v\n", newPlaintext)
	fmt.Printf("random key: %v\n", randomKey)


	return []byte("hi")
}