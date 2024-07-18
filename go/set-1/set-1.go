package main

import (
	"log"
	"encoding/hex"
	"encoding/base64"
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