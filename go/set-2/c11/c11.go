package main

import (
	"fmt"
	"log"
	"crypto/rand"
	"math/big"
)

func GenerateRandomAESKey(byteLength int) []byte {
	token := make([]byte, byteLength)

	_, err := rand.Read(token)
	if err != nil {
		log.Fatalf("error generating random key: %v", err)
	}

	return token
}

func GenerateRandomInt() int {
	min := big.NewInt(5)
	max := big.NewInt(10)
	diff := big.NewInt(0).Sub(max, min)
	diffPlusOne := big.NewInt(0).Add(diff, big.NewInt(1))

	nBig, err := rand.Int(rand.Reader, diffPlusOne)
	if err != nil {
		log.Fatalf("error generating random number: %v", err)
	}

	n := big.NewInt(0).Add(nBig, min).Int64()

	return int(n)
}

// Appends 5-10 random bytes before plaintext and 5-10 bytes after plaintext
// Encrypts ECB 1/2 the time and CBC other half - rand(2) each time to decide
// 	- uses random IVs each time for CBC
// Detects which mode (ECB || CBC) used
func EncryptionOracle(plaintext []byte) []byte {
	randomKey := GenerateRandomAESKey(16)	

	fmt.Printf("random key: %v\n", randomKey)
	fmt.Printf("random int: %v\n", GenerateRandomInt())


	return []byte("hi")
}