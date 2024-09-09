package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	// "fmt"
	"log"
	"math"
	"os"
	"path/filepath"
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
	- Breaks bytes into blocks that were encrypted using same single byte xor
	- returns new blocks where 1st block is the 1st byte of every block, 2nd is 2nd byte of every keySize block, and so on
	Ex:
	data: 			[abc123defg456]
	keysize blocks: [abc, 123, def, g45, 6]
	transposed: 	[a1dg6, b2d4, c3f5] each block here was encrypted with same key
		Example: 
		- Imagine the key was "KEY"
		- block at index 0 was encrtyped with char "K"
		- block at index 1 with "E"
		- block at index 2 with "Y"
*/
func TransposeBlocks(data []byte, keySize int) [][]byte {
	blocksEncryptedBySameKey := make([][]byte, keySize) // will have "keySize" amt of elements

	for i := 0; i < len(data); i++ {
		// append the byte into the block at "i % keySize"
		blocksEncryptedBySameKey[i % keySize] = append(blocksEncryptedBySameKey[i % keySize], data[i])
	}

	return blocksEncryptedBySameKey
}

/*
	- Solve each block as if it were single-char-xor.
	- Turn each block into hex and run it through GetKeyAndScoreForLine
	- Builds up each key as a string and returns it
*/
func getKeyFromBlocks(transposedBlocks [][]byte) string {

	keyBytes := make([]byte, 0)	

	for _, block := range transposedBlocks {
		key, _ := GetKeyAndScoreForLine(hex.EncodeToString(block))
		keyBytes = append(keyBytes, byte(key))
	}	

	return string(keyBytes)
}

func decodeBase64(data []byte) []byte {
	decoded, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		log.Fatalf("Base64 decoding error: %v", err)
	}

	return decoded
}

/* 
	- Reads a file that has been repeating key XOR encrypted and then base64 encoded.
	- Discovers the key used to encrypt the file
*/ 
func BreakRepeatingKeyXOR(fileName string) string {
	// Read the file, turns it into bytes, then decode it from bas64
	cipherData := readFileAsBytes(fileName)
	decodedCipherData := decodeBase64(cipherData)

	// Find the probable key length
	keySize := findProbableKeyLength(decodedCipherData)

	blocksEncryptedBySameKey := TransposeBlocks(decodedCipherData, keySize)

	return getKeyFromBlocks(blocksEncryptedBySameKey)
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

func DecryptFileAESinECBmode(fileName string, key string) string {
	// Read file and decode base64
	data := readFileAsBytes(fileName)
	decoded := decodeBase64(data)

	// Decrypt AES
	return DecryptAES(decoded, key)
}

func checkLineForDuplicates(blocks [][]byte) bool {
    // Use a map to track seen blocks
    seenBlocks := make(map[string]bool)

    // Iterate over the blocks
    for _, block := range blocks {
        // Convert the block to a string to use as a map key
        blockStr := string(block)

        // Check if the block has been seen before
        if _, exists := seenBlocks[blockStr]; exists {
            return true // Duplicate found
        }

        // Mark the block as seen
        seenBlocks[blockStr] = true
    }

    return false // No duplicates found
}

type AesECBDetection struct {
	index int
	line []byte
}

func findLineWithDuplicateBlocks(transposedLines [][][]byte, lines [][]byte) AesECBDetection {
	for i, line := range transposedLines {
		if hasDuplicates := checkLineForDuplicates(line); hasDuplicates {
			return AesECBDetection{
				index: i,
				line: lines[i],
			}
		}
	}

	return AesECBDetection{}
}

/* 
	- Reads file as independent lines
	- Turns each line into a list of lists of 16bytes:
		[
			[[16bytes], [16bytes], [16bytes]] line
			[[16bytes], [16bytes], [16bytes]] line
			...
		]
	- Figures out which line has duplicates and returns the index of that line and the line itself
*/
func DetectAESinECB(fileName string) AesECBDetection {
	file, err := os.Open(filepath.Join("..", "data", fileName))

	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	lines := make([][]byte, 0)
	transposedLines := make([][][]byte, 0)

	for scanner.Scan() {
		line := scanner.Bytes()

		// make copy of line and append into lines (scanner reuses internal buffer. Could create duplicates)
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		// populate the initial lines to return the line at the end with the index
		lines = append(lines, lineCopy)

		// turn lineCopy into [][]byte with each inner []byte containing 16 bytes
		lineInChunksOf16Bytes := make([][]byte, 0)

		for start := 0; start < len(lineCopy); start += 16 {
			end := start + 16

			// if out of bounds, set end to the last index + 1 (non inclusive end)
			if end > len(lineCopy) {
				end = len(lineCopy)
			}

			chunk := lineCopy[start:end]

			lineInChunksOf16Bytes = append(lineInChunksOf16Bytes, chunk)
		}

		transposedLines = append(transposedLines, lineInChunksOf16Bytes)
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
	}

	return findLineWithDuplicateBlocks(transposedLines, lines)
}