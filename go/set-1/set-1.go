package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	// "fmt"
	// "sync"

	// "io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
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

func getTextWithKey(hexInput string, key int) string {
	inputBytes, err := hex.DecodeString(hexInput)

	if err != nil {
		log.Fatal(err)
	}

	var decryptedBytes []byte = make([]byte, 0, len(inputBytes))

	for _, inputByte := range inputBytes {
		decrypted := inputByte ^ byte(key)
		decryptedBytes = append(decryptedBytes, byte(decrypted))
	}

	return string(decryptedBytes)
}

func FindEncryptionKeyForLine(hexInput string) (int, float32) {
	inputBytes, err := hex.DecodeString(hexInput)
	const largestHex = 0xFF

	if err != nil {
		log.Fatal(err)
	}

	var topScore float32 = 0
	var foundEncryptionKey = 0

	for key := 0; key < largestHex; key++ {
		// Todo: extract this out
		var decryptedBytes []byte = make([]byte, 0, len(inputBytes))

		for _, inputByte := range inputBytes {
			decrypted := inputByte ^ byte(key)
			decryptedBytes = append(decryptedBytes, byte(decrypted))
		}

		text := string(decryptedBytes)
		score := scoreEnglishText(text)

		if score > topScore {
			topScore = score
			foundEncryptionKey = key
		}
	}

	return foundEncryptionKey, topScore
}

func isPrintableAsci(text string) bool {
	re := regexp.MustCompile(`^[\x20-\x7E]*$`)

	return re.MatchString(text)
}

func scoreEnglishText(text string) float32 {
	if !isPrintableAsci(text) {
		return 0
	}

	var wordFrequencies map[rune]float32 = map[rune]float32{
		'e': 12.7, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
		's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.02, 'c': 2.78,
		'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
		'p': 1.93, 'b': 1.49, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
		'q': 0.095, 'z': 0.074, ' ': 13,
	}

	var score float32 = 0
	validCharCount := 0

	for _, char := range text {
		var val, ok = wordFrequencies[char]

		if ok {
			score += val
			validCharCount++
		}
	}

	if validCharCount > 0 {
		result := score / float32(validCharCount)

		return result
	}

	return 0
}

func FindEncyptionKeyInFile(fileName string) int {
	file, err := os.Open(filepath.Join("..", "data", fileName))

	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	topScore := float32(0)
	bestKey := 0

	for scanner.Scan() {
		line := scanner.Text()
		key, score := FindEncryptionKeyForLine(line)

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

	topScore := float32(0)
	bestText := ""

	for scanner.Scan() {
		line := scanner.Text()
		text := getTextWithKey(line, key)

		score := scoreEnglishText(text)
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
