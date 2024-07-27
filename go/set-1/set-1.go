package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
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

func FindEncyptionKey(hexInput string) int {
	inputBytes, err := hex.DecodeString(hexInput)
	const largestHex = 0xFF

	if err != nil {
		log.Fatal(err)
	}

	var topScore float32 = 0
	var foundEncryptionKey = 0

	for key := 0; key < largestHex; key++ {
		var decryptedBytes []byte = make([]byte, 0, len(inputBytes))

		for _, inputByte := range inputBytes {
			decrypted := inputByte ^ byte(key)
			decryptedBytes = append(decryptedBytes, byte(decrypted))
		}

		text := string(decryptedBytes)
		score := scoreEnglishText(text)

		if (score > topScore) {
			topScore = score
			foundEncryptionKey = key
		}
	}

	return foundEncryptionKey
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
