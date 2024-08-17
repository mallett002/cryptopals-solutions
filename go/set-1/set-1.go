package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
	- compares hamming distance of 4 chunks of keysize and gets an average hamming distance of that keysize
	- key length with lowest hamming distance is probably the key
*/
// This isn't working. Getting 3, but know it's 29
func findProbableKeyLength(data []byte) int {
	startKeySize := 2
	lowestAverage := math.MaxFloat64
	bestKeySize := startKeySize

	// for keySize := startKeySize; keySize <= 40; keySize++ {
	// 	if len(data) < keySize * 4 {
	// 		continue // Skip if not enough data for 4 chunks
	// 	}
	// 
	// 	keySizeChunks := [][]byte{
	// 		data[0:keySize],
	// 		data[keySize:keySize * 2],
	// 		data[keySize * 2:keySize * 3],
	// 		data[keySize * 3:keySize * 4],
	// 	}
	//
	// 	// compare chunks to get average hamming distance for this keySize
	// 	var averagesForKey []float64
	//
	// 	for i, chunk := range keySizeChunks {
	// 		for j := i + 1; j < len(keySizeChunks); j++ {
	// 			normalizedDistance := float64(GetHammingDistance(chunk, keySizeChunks[j])) / float64(keySize)
	// 			averagesForKey = append(averagesForKey, normalizedDistance)
	// 		}
	// 	}
	//
	// 	// Get overall average for key:
	// 	var overallAverageForKey float64
	// 	sum := float64(0.0)
	//	
	// 	for _, average := range averagesForKey {
	// 		sum += average
	// 	}
	//		
	// 	overallAverageForKey = sum / float64(len(averagesForKey))
	//	
	// 	// see if average for this key is smaller than current lowest average
	// 	if overallAverageForKey < lowestAverage {
	// 		lowestAverage = overallAverageForKey
	// 		bestKeySize = keySize
	// 	}
	// }

	
	return bestKeySize
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
	fmt.Printf("Probable key length: %v\n", keySize)

	// Find the key
	return "fooey"
}