package main

import (
	"fmt"
	"os"
	"path/filepath"
	"bufio"
	"log"
	"encoding/base64"
	"crypto/aes"
	"crypto/rand"
	"math/big"
	mathRand "math/rand"
	"time"
)

func PKSNumber7(input string, byteCount int) string {
	EOT := 4
	inputBytes := []byte(input)

	for len(inputBytes) < byteCount {
		inputBytes = append(inputBytes, byte(EOT))
	}

	return string(inputBytes)
}

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
	// file, err := os.Open(filepath.Join(".", fileName))
	file, err := os.Open(filepath.Join("..", "data", fileName))

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
	maxExclusive := big.NewInt(0).Add(diff, big.NewInt(1))

	nBig, err := rand.Int(rand.Reader, maxExclusive)
	if err != nil {
		log.Fatalf("error generating random number: %v", err)
	}

	n := big.NewInt(0).Add(nBig, minBig).Int64()

	return int(n)
}

func getBitTrueOrFalse() int {
	// Seed the random number generator
	mathRand.New(mathRand.NewSource(time.Now().UnixNano()))

	// Generate a random number between 0 and 1
	return mathRand.Intn(2)
}


func encryptAES_ECB(plainText []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	cipherText := make([]byte, len(plainText))
	amtOfBlocks := len(cipherText) / BLOCK_SIZE

	// break plainText into key-sized chunks and decrypt them chunk by chunk (ECB mode)
	for i := 0; i < amtOfBlocks; i++ {
		start := i * BLOCK_SIZE // 0
		end := (i + 1) * BLOCK_SIZE // 16

		cipher.Encrypt(cipherText[start:end], plainText[start:end])
	}

	return cipherText
}

// Appends 5-10 random bytes before plaintext and 5-10 bytes after plaintext
// Encrypts ECB 1/2 the time and CBC other half - rand(2) each time to decide
// 	- uses random IVs each time for CBC
// Detects which mode (ECB || CBC) used
func EncryptionOracle(plaintext []byte) []byte {
	key := GenerateRandomBytes(16)	
	prevText := GenerateRandomBytes(GenerateRandomInt(5, 10))
	postText := GenerateRandomBytes(GenerateRandomInt(5, 10))

	newPlaintext := append(prevText, plaintext...)
	newPlaintext = append(newPlaintext, postText...)

	// pick ECB or CBC 50% of time
	if getBitTrueOrFalse() == 1 {
		fmt.Println("Encrypting with ECB mode")
		return encryptAES_ECB(newPlaintext, key)
	} 

	fmt.Println("Encrypting with CBC mode")

	return encryptAESCBC(newPlaintext, key)
}