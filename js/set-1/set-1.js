function hexToBase64(hexStr) {
    return Buffer.from(hexStr, 'hex').toString('base64');
}

function xor(a, b) {
    const length = Math.max(a.length, b.length);
    const buffer = Buffer.allocUnsafe(length);

    for (let i = 0; i < length; i++) {
        buffer[i] = a[i] ^ b[i];
    }

    return buffer;
}

function generateXOR(source, comparator) {
    const bufferOne = Buffer.from(source, 'hex');
    const bufferTwo = Buffer.from(comparator, 'hex');

    return xor(bufferOne, bufferTwo).toString('hex');
}

module.exports = {
    hexToBase64,
    generateXOR,
};
