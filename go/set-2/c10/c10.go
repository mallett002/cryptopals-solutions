package main

import (
	"math"
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

	plainText := make([]byte, len(data))
	amtOfBlocks := len(plainText) / BLOCK_SIZE

	// break data into key-sized chunks and decrypt them chunk by chunk
	for i := 0; i < amtOfBlocks; i++ {
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		cipher.Decrypt(plainText[start:end], data[start:end])
	}

	return string(plainText)
}

func xor(prevBlock []byte, currBlock []byte) []byte {
	var maxLength = int(math.Max(float64(len(prevBlock)), float64(len(currBlock))))
	var xordBytes []byte = make([]byte, maxLength)

	for i := 0; i < maxLength; i++ {
		xordBytes[i] = prevBlock[i] ^ currBlock[i]
	}
	
	return xordBytes
}

func encryptAES(data []byte, key string) string {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	encryptedBytes := make([]byte, len(data))
	amtOfBlocks := len(encryptedBytes) / BLOCK_SIZE

	// break data into key-sized chunks and encrypt them chunk by chunk (ECB mode)
	for i := 0; i < amtOfBlocks; i++ {
		// - encrypt each block
		// - But before each encryption, XOR the plaintext block with the previous ciphertext block (starting with IV for first block)	
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		// XOR block with previous ciphertext
		var previousBlock []byte

		if i == 0 {
			previousBlock = getIV()
		} else {
			prevStart := (i - 1) * BLOCK_SIZE
			prevEnd := i * BLOCK_SIZE
			previousBlock = encryptedBytes[prevStart:prevEnd]
		}

		// XOR current plaintext block with previous ciphertext block:
		currentBlock := data[start:end]
		xordBytes := xor(previousBlock, currentBlock)

		cipher.Encrypt(encryptedBytes[start:end], xordBytes)
	}

	return string(encryptedBytes)
}

func ImplementCBCMode(fileName string, key string) string {
	data := readFileAsBytes(fileName)
	decoded := decodeBase64(data)

	return encryptAES(decoded, key)
}
