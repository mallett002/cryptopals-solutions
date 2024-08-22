package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	// "strings"

	// "fmt"
	// "sync"

	// "io"
	"log"
	"math"
	"os"
	"path/filepath"
	// "regexp"
)

func HexToBase64(input string) string {
	// turn hex to array of bytes
	bytes, err := hex.DecodeString(input)

	if err != nil {
		log.Fatal(err)
	}

	// turn array of bytes into base64
	return base64.StdEncoding.EncodeToString(bytes)
}

func XORHexStrings(source string, comparator string) string {
	sourceBytes, err := hex.DecodeString(source)

	if err != nil {
		log.Fatal(err)
	}

	comparatorBytes, err := hex.DecodeString(comparator)

	if err != nil {
		log.Fatal(err)
	}

	var maxLength = int(math.Max(float64(len(sourceBytes)), float64(len(comparatorBytes))))
	var xordBytes []byte = make([]byte, maxLength)

	for i := 0; i < maxLength; i++ {
		xordBytes[i] = sourceBytes[i] ^ comparatorBytes[i]
	}

	return hex.EncodeToString(xordBytes)
}

func getDecryptedBytes(hexInput string, key int) []byte {
	inputBytes, err := hex.DecodeString(hexInput)

	if err != nil {
		log.Fatal(err)
	}

	var decryptedBytes []byte = make([]byte, 0, len(inputBytes))

	for _, inputByte := range inputBytes {
		decrypted := inputByte ^ byte(key)
		decryptedBytes = append(decryptedBytes, byte(decrypted))
	}

	return decryptedBytes
}

func GetKeyAndScoreForLine(hexInput string) (int, int) {
	const largestHex = 0xFF

	var topScore int = 0
	var foundEncryptionKey = 0

	for key := 0; key < largestHex; key++ {
		var decryptedBytes []byte = getDecryptedBytes(hexInput, key)

		score := scoreBytes(decryptedBytes)

		if score > topScore {
			topScore = score
			foundEncryptionKey = key
		}
	}

	return foundEncryptionKey, topScore
}

func isAlphabetChar(bite byte) bool {
	return (bite >= 64 && bite <= 90) || (bite >= 97 && bite <= 122) || bite == 92
}

func isSpaceChar(bite byte) bool {
	return bite == 32
}

func isSpecialChar(bite byte) bool {
	return (bite >= 33 && bite <= 64) || (bite >= 93 && bite <= 96) || (bite >= 123 && bite <= 127) || bite == 91
}

func scoreBytes(buffer []byte) int {
	score := 0

	for _, bite := range buffer {
		bitten := byte(bite)

		switch {
		case isAlphabetChar(bitten):
			score += 20
		case isSpaceChar(bitten):
			score += 100
		case isSpecialChar(bitten):
			score += 10
		default:
			score -= 100
		}
	}

	return score
}

func FindEncyptionKeyInFile(fileName string) int {
	file, err := os.Open(filepath.Join("..", "data", fileName))

	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	topScore := 0
	bestKey := 0

	for scanner.Scan() {
		line := scanner.Text()
		key, score := GetKeyAndScoreForLine(line)

		if score > topScore {
			topScore = score
			bestKey = key
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
	}

	return bestKey
}

func FindTextFromFileWithKey(fileName string, key int) string {
	file, err := os.Open(filepath.Join("..", "data", fileName))

	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	topScore := 0
	bestText := ""

	for scanner.Scan() {
		line := scanner.Text()
		decryptedBytes := getDecryptedBytes(line, key)
		text := string(decryptedBytes)

		score := scoreBytes(decryptedBytes)
		if score > topScore {
			topScore = score
			bestText = text
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
	}

	return bestText
}

/*
 	* Sequentially XOR each byte of the key to the plainText. *
		* Ex: Text: Hello; Key: ICE
			* H ^ I, e ^ C, l ^ E, l ^ I... etc
 	* Returns the encrypted string result of the sequential XOR.
*/
func RepeatingKeyXOR(text string, key string) string {
	textBytes := []byte(text)
	keyBytes := []byte(key)

	encryptedBytes := make([]byte, 0, len(textBytes))

	for i, bite := range textBytes {
		keyIndex := i % len(keyBytes)
		encryptedBytes = append(encryptedBytes, bite ^ keyBytes[keyIndex])
	}

	return hex.EncodeToString(encryptedBytes)
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// Gets amount of differing bites for aBytes and bBytes
func GetHammingDistance(aBytes []byte, bBytes []byte) int {
	length := max(len(aBytes), len(bBytes))

	differingBitCount := 0

	for i := 0; i < length; i++ {
		xor := aBytes[i] ^ bBytes[i]

		for xor != 0 {
			differingBitCount += int(xor & 1)
			xor = xor >> 1
		}
	}

	return differingBitCount
}

func readFileAsBytes(fileName string) []byte {
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

/*
	- Tries to discover key length
	- Breaks the data into chunks of estimated keysize (2 - 40)
	- compares hamming distance of 2 consecutive chunks of size "keysize" and gets an average hamming distance of that keysize
	- key length with lowest hamming distance is probably the key
*/
func findProbableKeyLength(data []byte) int {
	smallestAverage := math.MaxFloat64
	bestKey := 2

	for maybeKeySize := 2; maybeKeySize <= 41; maybeKeySize++ { // for each potential keySize
		amtOfChunks := len(data) / maybeKeySize
		averagesForKey := make([]float64, 0)

		// build up distances per key
		for i := 0; i < amtOfChunks - 1; i++ {
			chunkOne := data[i * maybeKeySize : (i + 1) * maybeKeySize]
			chunkTwo := data[(i + 1) * maybeKeySize : (i + 2) * maybeKeySize]

			distance := GetHammingDistance(chunkOne, chunkTwo)
			aveDistancePerKey := float64(distance) / float64(maybeKeySize)
			averagesForKey = append(averagesForKey, aveDistancePerKey)
		} 
		
		// determine best key (one with the smallest total average)
		sum := float64(0)
		for _, ave := range averagesForKey {
			sum += ave
		}
		aveForKey := sum / float64(len(averagesForKey))

		if (aveForKey < smallestAverage) {
			bestKey = maybeKeySize
			smallestAverage = aveForKey
		}
	}

	return bestKey
}

/*
	- Breaks bytes into blocks
	- returns new blocks where 1st block is the 1st byte of every block, 2nd is 2nd byte of every keySize block, and so on
	Ex:
	data: 			[abc123defg456]
	keysize blocks: [abc, 123, def, g45, 6]
	transposed: 	[a1dg6, ]


*/
func TransposeBlocks(data []byte, keySize int) [][]byte {
	keySizedBlocks := make([][]byte, 0)

	// First put them in keysize blocks:
	for i := 0; i < len(data); i += keySize {
		keySizedBlocks = append(keySizedBlocks, data[i : i + keySize])		
	}

	// then transpose them
	transposedBlocks := make([][]byte, 0)

	for i := 0; i < keySize; i++ {
		block := make([]byte, 0)

		for _, keySizedBlock := range keySizedBlocks {
			if i > len(keySizedBlock) - 1 {
				continue
			}

			block = append(block, keySizedBlock[i])
		}	

		transposedBlocks = append(transposedBlocks, block)
	}

	return transposedBlocks
}

// Todo: this function needs work, not quite right
func getKeyFromBlocks(transposedBlocks [][]byte) string {
	// solve each block as if it were single-char-xor
		// turn each block into hex and run it through GetKeyAndScoreForLine

	keyBytes := make([]byte, 0)	

	for _, block := range transposedBlocks {
		key, _ := GetKeyAndScoreForLine(hex.EncodeToString(block))
		keyBytes = append(keyBytes, byte(key))
	}	

	return string(keyBytes)
}

/* 
	- Reads a file that has been repeating key XOR encrypted and then base64 encoded.
	- Discovers the key used to encrypt the file
*/ 
func BreakRepeatingKeyXOR(fileName string) string {
	// Read the file, turns it into bytes
	cypherData := readFileAsBytes(fileName)

	// Find the probable key length
	keySize := findProbableKeyLength(cypherData)
	transposedBlocks := TransposeBlocks(cypherData, keySize)

	return getKeyFromBlocks(transposedBlocks)
}
