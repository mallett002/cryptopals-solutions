function hexToBase64(hexStr) {
    return Buffer.from(hexStr, 'hex').toString('base64');
}

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

// This is a naive approach
function scoreText(text) {
    console.log({textIs: text});
    const spaces = text.match(/\s/g);

    console.log({spaces});

    if (spaces && spaces.length) {
        return spaces.length
    }

    return 0;
}

// Determine which key was used to encrypt the given hex string
function findEncyptionKey(hexString) {
    const inputBytes = Buffer.from(hexString, 'hex');
    const largestHexLiteral = 0xFF; // 255
    
    let encryptionKey = '';
    let hiddenMessage = '';
    let highestScore = 0;

    /* For each byte in all possible hex bytes, XOR against the input "hexString"'s bytes
    to produce a decrypted message */
    for (let key = 0; key <= largestHexLiteral; key++) {
        const decryptedBytes = inputBytes.map((byte) => byte ^ key);
        const decryptedText = Buffer.from(decryptedBytes).toString('utf8');

        if (isPrintableAscii(decryptedText)) {
            console.log({decryptedText});
            const score = scoreText(decryptedText);

            if (score > highestScore) {
                highestScore = score;
                encryptionKey = key;
                hiddenMessage = decryptedText;
            }
        }
    }

    console.log('The message is: ', hiddenMessage);
    console.log('The highest score is: ', highestScore);
    console.log('The key in utf8 is: ', `"${Buffer.from([encryptionKey]).toString('utf8')}"`);

    return encryptionKey;
}

module.exports = {
    hexToBase64,
    xorHexStrings,
    findEncyptionKey,
};
