const crypto = require('node:crypto');
const fs = require('fs');
const path = require('path');
const { log } = require('node:console');

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
function findEncryptionKey(hexString) {
    const largestHexLiteral = 0xFF; // 255
    let encryptionKey = '';
    let hiddenMessage = '';
    let highestScore = 0;

    /* For each byte in all possible hex bytes, XOR against the input "hexString"'s bytes
    to produce a decrypted message */
    for (let key = 0; key <= largestHexLiteral; key++) {
        const { score, decryptedText } = _decryptHexLineWithKey(hexString, key);

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
 * Single Byte XOR - Decrypts each byte of hexString with the given key and scores the decrypted text against English text
 *
 * @param {string} hexString - The hexadecimal string to analyze.
 * @param {number} key - The key to decrypt each byte of hexString against
 * @returns {{score: number, key: number, decryptedText: string}} An object containing the score, key, and decrypted text.
 */
function _decryptHexLineWithKey(hexString, key) {
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
    const file = fs.readFileSync(path.join(__dirname, '..', 'data', fileName), 'utf-8');
    const lines = file.split('\n');

    let highestScore = 0;
    let foundKey = null;
    let englishText = '';

    for (const line of lines) {
        const { key, score, text } = findEncryptionKey(line);

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
        const { score, decryptedText } = _decryptHexLineWithKey(line, key);

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

function getHammingDistance(aBytes, bBytes) {
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

// Takes in binary data and split it into incremental chunks.
// Finds the chunk size with the lowest average hamming distance (most similar bits)
function _findProbableKeySize(cipherData) {
    let keySizeWithSmallestHammingDistance = 2;
    let smallestNormalizedDistance = Infinity;

    // create 4 chunks of size key and get hemming distance against each other
    // keySize that has the shortest average hemming distance is the found keySize
    for (let keySize = 2; keySize <= 40; keySize++) {
        const chunks = [
            cipherData.subarray(0, keySize),
            cipherData.subarray(keySize, keySize * 2),
            cipherData.subarray(keySize * 2, keySize * 3),
            cipherData.subarray(keySize * 3, keySize * 4),
        ];
        const averagesForKey = [];

        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];

            // look at other chunks and get hamming distance of them
            for (let j = 0; j < chunks.length; j++) {
                if (j === i) {
                    continue;
                }

                const otherChunk = chunks[j];

                const hammingDistance = getHammingDistance(chunk, otherChunk);
                const normalizedDistance = hammingDistance / keySize;

                averagesForKey.push(normalizedDistance);
            }
        }

        const average = averagesForKey.reduce((sum, curr) => sum + curr, 0) / averagesForKey.length;

        if (average < smallestNormalizedDistance) {
            keySizeWithSmallestHammingDistance = keySize;
            smallestNormalizedDistance = average;
        }

    }

    return keySizeWithSmallestHammingDistance;
}

function _readAndBase64Decode(fileName) {
    const file = fs.readFileSync(path.join(__dirname, '..', 'data', fileName), 'utf-8');

    return Buffer.from(file, 'base64');
}

// Make a block, of size keysize, that is the first byte of every block, and a block that is the second byte of every block, and so on.
function _transposeKeySizedBlocks(data, keySize) {
    const blocks = Array.from({ length: keySize }, () => []);

    for (let i = 0; i < data.length; i++) {
        blocks[i % keySize].push(data[i]);
    }

    return blocks.map(block => Buffer.from(block));
}

// Turn into hex, find encryption key, build up string from bytes (keys)
function _determineKey(transposedBlocks) {
    let key = '';

    for (const block of transposedBlocks) {
        const hexBlock = block.toString('hex');
        const { key: singleByteKey } = findEncryptionKey(hexBlock);
        
        key += String.fromCharCode(singleByteKey);
    }

    return key;
}

// Finds the key used to encrypt the file
function breakRepeatingKeyXOR(fileName) {
    const cipherData = _readAndBase64Decode(fileName);
    const keySize = _findProbableKeySize(cipherData);
    const transposedBlocks = _transposeKeySizedBlocks(cipherData, keySize);

    return _determineKey(transposedBlocks);
}

function repeatingKeyXORForFile(fileName, key) {
    const cipherData = _readAndBase64Decode(fileName);

    // This is doing what repeatingKeyXOR is doing:
    const keyBytes = Buffer.from(key, 'utf8');
    const buffer = Buffer.alloc(cipherData.length);

    for (let i = 0; i < cipherData.length; i++) {
        const keyIndex = i % key.length;

       // xor them 
        buffer[i] = cipherData[i] ^ keyBytes[keyIndex];
    }

    return buffer.toString('utf8');
}

// AES decrypt
// AES: symmetric block cipher that decrypts in fixed-sized blocks (e.g., 128 bits for AES)
// ECB mode: encrypts each block independently
// symmetric block cipher: type of cipher that uses same key for encryption/decryption
    // block cipher: processed in fixed sized chunks
function decryptAES(cipherText, key) {
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);

    let result = decipher.update(cipherText, 'binary', 'utf8');

    result += decipher.final('utf8');

    return result;
}

function decryptFileAESinECBmode(fileName, key) {
    // base64 decode the ciphertext
    const cipherText = _readAndBase64Decode(fileName);
    
    // AES decrypt
    return decryptAES(cipherText, key);
}

/**
 * Reads a file with hex-encoded AES-ECB encrypted ciphertexts, 
 * converts each line into a byte array, and splits each byte array into blocks of 16 bytes.
 *
 * @param {string} fileName - The name of the file to be read. Each line in the file is a hex-encoded ciphertext.
 * @returns {Array<Array<Buffer>>} - A list of lists where each inner array represents a line of ciphertext 
 *                                   divided into 16-byte blocks.
 *                                   Format: [[[16Bytes, 16Bytes, ...]], [[16Bytes, 16Bytes, ...]], ...]
 */
function _readFileAndTransposeIntoBlocksOf16Bytes(fileName) {
    const file = fs.readFileSync(path.join(__dirname, '..', 'data', fileName), 'utf-8'); // simply read in the file as text
    const buffers = file.split('\n').map(line => Buffer.from(line, 'hex')); // create a list of buffers that hold bytes for each line (they are hex, so treat them accordingly)

    // Create the final structure: a list of lists where each inner list contains 16-byte blocks
    const buffersInBlocksOf16Bytes = buffers.map(buffer => {
        const blocks = [];

        for (let i = 0; i < buffer.length; i += 16) {
            blocks.push(buffer.subarray(i, i + 16)); // Split buffer into 16-byte blocks
        }

        return blocks;
    });

    return buffersInBlocksOf16Bytes;
}

// check if block shows up in blocks more than once
// blocks: [[16Bytes], [16Bytes], ...]]
// blocks represents a line. An array of Buffers
// if there is a buffer that shows up more than once, returns true
function checkContainsDuplicates(buffers) {
    const visited = [];

    for (let i = 0; i < buffers.length; i++) {
        const buffer = buffers[i];

        if (visited.some((visitedBuffer) => visitedBuffer.equals(buffer))) {
            return true;
        }

        visited.push(buffer);
    }

    return false;
}

/*
1. Convert Hex-Encoded Ciphertext into Bytes:
    The ciphertexts provided are in hexadecimal form. You’ll need to convert each hex string into its corresponding byte array for processing.

2. Divide Each Ciphertext into Blocks:
    AES uses a block size of 16 bytes (128 bits). After converting the ciphertext to bytes, you need to divide it into 16-byte blocks.
    
3. Detect Repeated Blocks:
    ECB mode will produce identical ciphertext blocks for identical plaintext blocks. This is a key characteristic of ECB’s deterministic nature.
    Look for repeated blocks within each ciphertext. If a ciphertext has any repeated 16-byte blocks, it’s very likely encrypted with ECB.

4. Identify the Ciphertext with Repeats:
    The ciphertext that contains repeated blocks is the one encrypted with ECB. Return or print the index or the actual ciphertext.
*/
function detectAESinECB(fileName) {
    const ciphersInBlocksOf16Bytes = _readFileAndTransposeIntoBlocksOf16Bytes(fileName);

    for (let i = 0; i < ciphersInBlocksOf16Bytes.length; i++) {
        const line = ciphersInBlocksOf16Bytes[i];

        // check if this line has any duplicates, if so we found the one encrypted with AES in ECB mode
        if (checkContainsDuplicates(line)) {
            return { index: i, line }
        }
    }

    return { index: -1, line: '' };
}

module.exports = {
    hexToBase64,
    xorHexStrings,
    findEncryptionKey,
    xorDecrypt,
    findEncyptionKeyInFile,
    findTextFromFileWithKey,
    repeatingKeyXOR,
    getHammingDistance,
    breakRepeatingKeyXOR,
    repeatingKeyXORForFile,
    decryptFileAESinECBmode,
    detectAESinECB,
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
