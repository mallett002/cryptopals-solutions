package main

import (
	"crypto/rand"
)

func GenerateRandomAESKey() []byte {
	token := make([]byte, 16)

	return rand.Reader.Read(token)
}

// 
func EncryptionOracle(input []byte) []byte {

	return []byte("hi")
}