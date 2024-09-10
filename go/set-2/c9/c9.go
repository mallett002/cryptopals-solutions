package main

func PKSNumber7(input string, byteCount int) string {
	EOT := 4
	inputBytes := []byte(input)

	for len(inputBytes) < byteCount {
		inputBytes = append(inputBytes, byte(EOT))
	}

	return string(inputBytes)
}
