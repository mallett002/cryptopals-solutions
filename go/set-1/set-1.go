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

	for key := 0; key < largestHex; key++ {
		var decryptedBytes []byte = make([]byte, 0, len(inputBytes))

		for _, inputByte := range inputBytes {
			decrypted := inputByte ^ byte(key)
			decryptedBytes = append(decryptedBytes, byte(decrypted))
		}

		text := string(decryptedBytes)
		score := scoreEnglishText(text)

		if score > 0 {
			fmt.Printf("Key: %d, Text: %s\n", key, text)
		}

	}

	return 0
}

func isPrintableAsci(text string) bool {
	re := regexp.MustCompile(`^[\x20-\x7E]*$`)

	return re.MatchString(text)
}

func scoreEnglishText(text string) int {
	if !isPrintableAsci(text) {
		return 0
	}

	// Todo: score this based on English letter frequency

	return 5
}
