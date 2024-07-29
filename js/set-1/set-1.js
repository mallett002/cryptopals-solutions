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
    const inputBytes = Buffer.from(hexString, 'hex');
    const largestHexLiteral = 0xFF; // 255

    let encryptionKey = '';
    let hiddenMessage = '';
    let highestScore = 0;

    /* For each byte in all possible hex bytes, XOR against the input "hexString"'s bytes
    to produce a decrypted message */
    for (let key = 0; key <= largestHexLiteral; key++) {
        const decryptedBytes = inputBytes.map((byte) => byte ^ key); // decrypt each byte
        const decryptedText = Buffer.from(decryptedBytes).toString('utf8'); // turn each byte into utf8 (text)
        const score = scoreBytes(decryptedBytes);

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

module.exports = {
    hexToBase64,
    xorHexStrings,
    findEncyptionKey,
    xorDecrypt,
    findEncyptionKeyInFile
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
