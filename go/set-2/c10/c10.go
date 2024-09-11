package main

import (
	"os"
	"path/filepath"
	"bufio"
	"log"
	"encoding/base64"
	"crypto/aes"
)

const BLOCK_SIZE = 16

func getIV() []byte {
	iv := ""

	for i := 0; i < BLOCK_SIZE; i++ {
		iv += "\x00"
	}

	return []byte(iv)
}

func readFileAsBytes(fileName string) []byte {
	file, err := os.Open(filepath.Join(".", fileName))

	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	var data []byte

	for scanner.Scan() {
		data = append(data, scanner.Bytes()...)
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
	}

	return data
}

func decodeBase64(data []byte) []byte {
	decoded, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		log.Fatalf("Base64 decoding error: %v", err)
	}

	return decoded
}

func DecryptAES(data []byte, key string) string {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	blockSize := len(key) // 16
	plainText := make([]byte, len(data))
	amtOfBlocks := len(plainText) / blockSize

	// break data into key-sized chunks and decrypt them chunk by chunk (ECB mode)
	for i := 0; i < amtOfBlocks; i++ {
		start := i * blockSize // 0
		end := (i + 1) * blockSize // 16

		cipher.Decrypt(plainText[start:end], data[start:end])
	}

	return string(plainText)
}

func encryptAES(data []byte, key string) string {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	blockSize := len(key)
	plainTextBlocks := make([]byte, len(data))
	amtOfBlocks := len(plainText) / blockSize

	// break data into key-sized chunks and encrypt them chunk by chunk (ECB mode)
	for i := 0; i < amtOfBlocks; i++ {
		// - encrypt each block
		// - But before each encryption, XOR the plaintext block with the previous ciphertext block (starting with IV for first block)	

		// stuck here..
		if i == 0 {
			plainTextBlocks[i] ^ getIV()
		} else {
			// What I was doing for decryption:
			// start := i * blockSize // 0
			// end := (i + 1) * blockSize // 16

			// cipher.Encrypt(plainText[start:end], data[start:end])
		}

	}

	return string(plainTextBlocks)
}

func ImplementCBCMode(fileName string, key string) string {
	data := readFileAsBytes(fileName)
	decoded := decodeBase64(data)

	return encryptAES(decoded, key)
}
