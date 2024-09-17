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

/*
	Encrypt:
		- XOR prev cipherText, starting with IV, with current plaintext block
		- encrypt the result

	Decrypt:
		- decrypt to get the XOR'd version
		- XOR block with prev plainText starting with IV
*/
func DecryptAESECB(cipheredBytes []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	xoredBytes := make([]byte, len(cipheredBytes))
	plainTextBytes := make([]byte, len(cipheredBytes))
	amtOfBlocks := len(plainTextBytes) / BLOCK_SIZE

	cipher.Decrypt(xoredBytes, cipheredBytes)

	// break cipheredBytes into key-sized chunks and decrypt them chunk by chunk
	for i := 0; i < amtOfBlocks; i++ {
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		var prevBlock []byte = getIV()
		if i != 0 {
			prevBlock = xoredBytes[(i - 1) * BLOCK_SIZE : start]
		}

		currentBlock := xoredBytes[start:end]

		plainTextBytes = append(plainTextBytes, xor(prevBlock, currentBlock)...)
	}

	return plainTextBytes
}

func xor(prevBlock []byte, currBlock []byte) []byte {
	var xordBytes []byte = make([]byte, BLOCK_SIZE)

	for i := 0; i < BLOCK_SIZE; i++ {
		xordBytes[i] = prevBlock[i] ^ currBlock[i]
	}
	
	return xordBytes
}

func padPKCS7(data []byte) []byte {
	EOT := 4
	amtOfPadding := 0
	
	for len(data) % BLOCK_SIZE != 0 {
		amtOfPadding++
		data = append(data, byte(EOT))
	}

	return data
}

func encryptAESECB(data []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	encryptedBytes := make([]byte, len(data))
	amtOfBlocks := len(encryptedBytes) / BLOCK_SIZE

	// break data into key-sized chunks and encrypt them chunk by chunk (ECB mode)
	for i := 0; i < amtOfBlocks; i++ {
		// - encrypt each block
		// - But before each encryption:
		// 	- XOR the plaintext block with the previous ciphertext block (starting with IV for first block)	
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		// Get previous block
		var previousBlock []byte

		if i == 0 {
			previousBlock = getIV()
		} else {
			prevStart := (i - 1) * BLOCK_SIZE
			prevEnd := i * BLOCK_SIZE
			previousBlock = encryptedBytes[prevStart:prevEnd]
		}

		// XOR current plaintext block with previous ciphertext block
		currentBlock := data[start:end]
		xordBytes := xor(previousBlock, currentBlock)

		// Do encryption
		cipher.Encrypt(encryptedBytes[start:end], xordBytes)
	}

	return encryptedBytes
}

func ImplementCBCMode(fileName string, key []byte) []byte {
	data := readFileAsBytes(fileName)
	decoded := decodeBase64(data)
	padded := padPKCS7(decoded)

	return encryptAESECB(padded, key)
}
