const fs = require('fs');
const path = require('path');

function hexToBase64(hexStr) {
    return Buffer.from(hexStr, 'hex').toString('base64');
}

// XOR each byte to create new array of bytes
function xor(a, b) {
    const length = Math.max(a.length, b.length);
    const buffer = Buffer.alloc(length);

    for (let i = 0; i < length; i++) {
        buffer[i] = a[i] ^ b[i];
    }

    return buffer;
}

function xorHexStrings(source, comparator) {
    const bufferOne = Buffer.from(source, 'hex');
    const bufferTwo = Buffer.from(comparator, 'hex');

    return xor(bufferOne, bufferTwo).toString('hex');
}

function isPrintableAscii(text) {
    return /^[\x20-\x7E]*$/.test(text);
}

function scoreEnglishText(text) {
    if (!isPrintableAscii(text)) {
        return 0;
    }

    const frequencyMap = {
        e: 12.7, t: 9.06, a: 8.17, o: 7.51, i: 6.97, n: 6.75,
        s: 6.33, h: 6.09, r: 5.99, d: 4.25, l: 4.02, c: 2.78,
        u: 2.76, m: 2.41, w: 2.36, f: 2.23, g: 2.02, y: 1.97,
        p: 1.93, b: 1.49, v: 0.98, k: 0.77, j: 0.15, x: 0.15,
        q: 0.095, z: 0.074, ' ': 13
    };

    let score = 0;
    let validCharCount = 0;

    for (const char of text) {
        const lower = char.toLowerCase();

        if (frequencyMap[lower]) {
            score += frequencyMap[lower];
            validCharCount++;
        }
    }

    score = validCharCount > 0 ? score / validCharCount : 0;

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

        const score = scoreEnglishText(decryptedText);

        if (score > highestScore) {
            highestScore = score;
            encryptionKey = key;
            hiddenMessage = decryptedText;
        }
    }

    console.log('The message is: ', hiddenMessage);
    console.log('The highest score is: ', highestScore);
    console.log('The key in utf8 is: ', `"${Buffer.from([encryptionKey]).toString('utf8')}"`);

    return {
        key: encryptionKey,
        score: highestScore,
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
    // find encryption key
    // find the item with the highest score
    // return key
    const readLines = await new Promise((resolve, reject) => {
        const stream = fs.createReadStream(path.join(__dirname, '..', 'data', fileName), 'utf-8');

        const lines = [];

        stream.on('error', (error) => {
            console.log(`error: ${error.message}`);
            reject(error);
        });

        stream.on('data', (line) => {
            const splitLines = line.split('\n');

            for (it of splitLines) {
                lines.push(it);
            }
        });

        stream.on('end', () => {
            resolve(lines);
        });

    });

    let highestScore = 0;
    let foundKey = null;

    for (const line of readLines) {
        const { key, score } = findEncyptionKey(line);

        if (score > highestScore) {
            highestScore = score;
            foundKey = key;
        }
    }

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
