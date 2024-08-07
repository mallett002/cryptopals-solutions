const { log } = require('console');
const fs = require('fs');
const path = require('path');

function hexToBase64(hexStr) {
    // Turn string into binary from hex and then turn into base64 string
    return Buffer.from(hexStr, 'hex').toString('base64');
}

// XOR each byte to create new array of bytes
function xor(bufferOne, bufferTwo) {
    const length = Math.max(bufferOne.length, bufferTwo.length);
    const buffer = Buffer.alloc(length); // creates new buffer of size of longest input

    for (let i = 0; i < length; i++) {
        buffer[i] = bufferOne[i] ^ bufferTwo[i];
    }

    return buffer;
}

function xorHexStrings(source, comparator) {
    const sourceBytes = Buffer.from(source, 'hex');
    const comparatorBytes = Buffer.from(comparator, 'hex');

    return xor(sourceBytes, comparatorBytes).toString('hex');
}

function isAlphabetChar(byte) {
    return (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || byte === 92;
}

function isSpaceChar(byte) {
    return byte === 32;
}

function isSpecialChar(byte) {
    return (byte >= 33 && byte <= 64) || (byte >= 93 && byte <= 96) || (byte >= 123 && byte <= 127) || byte === 91;
}

function scoreBytes(buffer) {
    let score = 0;

    for (const byte of buffer) {
        if (isAlphabetChar(byte)) {
            score += 20;
        } else if (isSpaceChar(byte)) {
            score += 100;
        } else if (isSpecialChar(byte)) {
            score += 10;
        }
        else {
            score -= 100;
        }
    }

    return score;
}

/**
 * Determines which single-byte key was used to encrypt the given hex string.
 *
 * @param {string} hexString - The hexadecimal string to analyze.
 * @returns {number} The encryption key used as a decimal value.
 */
function findEncyptionKey(hexString) {
    const largestHexLiteral = 0xFF; // 255
    let encryptionKey = '';
    let hiddenMessage = '';
    let highestScore = 0;

    /* For each byte in all possible hex bytes, XOR against the input "hexString"'s bytes
    to produce a decrypted message */
    for (let key = 0; key <= largestHexLiteral; key++) {
        const { score, decryptedText } = decryptHexLineWithKey(hexString, key);

        if (score > highestScore) {
            highestScore = score;
            encryptionKey = key;
            hiddenMessage = decryptedText;
        }
    }

    return {
        key: encryptionKey,
        score: highestScore,
        text: hiddenMessage
    };
}

function decryptHexLineWithKey(hexString, key) {
    const decryptedBytes = Buffer.from(hexString, 'hex').map((byte) => byte ^ key); // decrypt each byte
    const decryptedText = Buffer.from(decryptedBytes).toString('utf8'); // turn each byte into utf8 (text)
    const score = scoreBytes(decryptedBytes);

    return {
        score,
        key,
        decryptedText,
    }
}

/**
 * Decrypts a hexadecimal string using a single-byte XOR key.
 *
 * @param {string} hexString - The hexadecimal string to decrypt.
 * @param {number} key - The single-byte XOR key used for decryption.
 * @returns {string} The decrypted string.
 */
function xorDecrypt(hexString, key) {
    const hex = Buffer.from(hexString, 'hex');

    let result = '';

    for (let i = 0; i < hex.length; i++) {
        result += String.fromCharCode(hex[i] ^ key);
    }

    return result;
}


/**
 * Reads file, for each hex line decrypts with all possible hex bytes. *
 * Returns the key (byte) that finds the decrypted text most similar to english text
 *
 * @param {string} fileName - The name of the file to read.
 * @returns {number} The byte that was used to encrypt (XORing) in decimal.
 */
async function findEncyptionKeyInFile(fileName) {
    // read from the file
    const file = fs.readFileSync(path.join(__dirname, '..', 'data', fileName), 'utf-8');
    const lines = file.split('\n');

    let highestScore = 0;
    let foundKey = null;
    let englishText = '';

    for (const line of lines) {
        const { key, score, text } = findEncyptionKey(line);

        if (score > highestScore) {
            highestScore = score;
            foundKey = key;
            englishText = text;
        }
    }

    console.log('Found text: ', englishText);
    console.log('highestScore: ', highestScore);
    return foundKey;
};


/**
 * Reads file, for each hex line decrypts with the provided key. *
 * Returns the decrypted line that mostly resembles english text from the provided file. 
 *
 * @param {string} fileName - The name of the file to read.
 * @returns {number} The byte that was used to encrypt (XORing) in decimal.
 */
function findTextFromFileWithKey(fileName, key) {
    const file = fs.readFileSync(path.join(__dirname, '..', 'data', fileName), 'utf-8');
    const lines = file.split('\n');

    let foundText = '';
    let highestScore = 0;

    for (const line of lines) {
        const { score, decryptedText } = decryptHexLineWithKey(line, key);

        if (score > highestScore) {
            highestScore = score;
            foundText = decryptedText;
        }
    }

    return foundText;
}

/**
 * Sequentially XOR each byte of the key to the plainText. *
 * Returns the encrypted string result of the sequential XOR.
 *
 * @param {string} plainText - The value to encrypt
 * @param {string} key - The value to encrypt against
 * @returns {number} The result of XOR'ing 
 */
function repeatingKeyXOR(plainText, key) {
    const plainTextBytes = Buffer.from(plainText, 'utf8');
    const keyBytes = Buffer.from(key, 'utf8');
    const buffer = Buffer.alloc(plainTextBytes.length);

    // index:    0, 1, 2, 3, 4, 5, 6, 7, 8
    // keyIndex: 0, 1, 2, 0, 1, 2, 0, 1, 2

    for (let i = 0; i < plainTextBytes.length; i++) {
        const keyIndex = i % key.length;

       // xor them 
        buffer[i] = plainTextBytes[i] ^ keyBytes[keyIndex];
    }

    return buffer.toString('hex');
}

function getHammingDistance(a, b) {
    const aBytes = Buffer.from(a, 'utf8');
    const bBytes = Buffer.from(b, 'utf8');
    const length = Math.max(aBytes.length, bBytes.length);

    let differingBitCount = 0;

    for (let i = 0; i < length; i++) {
        // how this works. take these 2 nibbles:
        // 1:   0101 
        // 2:   1101
        // xor: 1000

        // xor & 1: compares each rightmost digit with 1. If 1 if both are 1

        // 1000 >>= 1 shifts bits 1 to the right:
        // ex:
        //   0100 
        //   0010
        //   0001
        //   0000

        // look at each byte:
        const byteA = aBytes[i] || 0;
        const byteB = bBytes[i] || 0;

        let xor = byteA ^ byteB; // get the diff (xor)

        while (xor !== 0) { // all shifted to the right (0000)
            differingBitCount += xor & 1; // is the right most digit a 1
            xor >>= 1; // shift 1 to the right to look at next bits
        }
    }

    return differingBitCount;
}

module.exports = {
    hexToBase64,
    xorHexStrings,
    findEncyptionKey,
    xorDecrypt,
    findEncyptionKeyInFile,
    findTextFromFileWithKey,
    repeatingKeyXOR,
    getHammingDistance
};

// 1111
// binary: 16 8 4 2 1
//                 2^2(4) | 2^1(2) | 2^0(1)

// Binary to Hex -----------------------
//              0001 0011 0101 
// decimal:        1    3    5
// hex:            1    3    5
// result:                 135

// 1001 0111 1101
//    9    7   13
//    9    7    D
