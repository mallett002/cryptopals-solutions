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

func GetIV() []byte {
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
func DecryptAESCBC(cipheredBytes []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	plainTextBytes := make([]byte, len(cipheredBytes))
	amtOfBlocks := len(plainTextBytes) / BLOCK_SIZE

	// start prev plaintext block with the IV
	var prevBlock []byte = getIV()

	for i := 0; i < amtOfBlocks; i++ {
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		// Decrypt the current block
		var decryptedBlock []byte = make([]byte, BLOCK_SIZE)

		cipher.Decrypt(decryptedBlock, cipheredBytes[start:end])

		// XOR decrypted block with previous ciphertext
		currentPlainText := xor(prevBlock, decryptedBlock)

		// store result in plaintext slice
		copy(plainTextBytes[start:end], currentPlainText)

		// set prevBlock to current ciphertext block
		prevBlock = cipheredBytes[start:end]
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

/*
	* Encrypt AES in CBC mode:
		* Takes previously encrypted block (cipherText), starting with IV, and XORs it with the current plaintext block
		* Encrypts the XOR result and appends the encrypted block to the ciphertext result
*/
func encryptAESCBC(data []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	encryptedBytes := make([]byte, len(data))
	amtOfBlocks := len(encryptedBytes) / BLOCK_SIZE

	// Start previous cipherText block with IV (Initialization Vector)
	var previousBlock []byte = getIV()

	// break data into key-sized chunks and encrypt them chunk by chunk
	for i := 0; i < amtOfBlocks; i++ {
		// - encrypt each block
		// - But before each encryption:
		// 	- XOR the plaintext block with the previous ciphertext block (starting with IV for first block)	
		start := i * BLOCK_SIZE
		end := (i + 1) * BLOCK_SIZE

		// XOR current plaintext block with previous ciphertext block
		currentBlock := data[start:end]
		xordBytes := xor(previousBlock, currentBlock)

		// Do encryption
		cipher.Encrypt(encryptedBytes[start:end], xordBytes)

		previousBlock = encryptedBytes[start:end]
	}

	return encryptedBytes
}

func ImplementCBCMode(fileName string, key []byte) []byte {
	data := readFileAsBytes(fileName)
	decoded := decodeBase64(data)

	return encryptAESCBC(decoded, key)
}
