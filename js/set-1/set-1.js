function hexToBase64(hexStr) {
    return Buffer.from(hexStr, 'hex').toString('base64');
}

module.exports = {
    hexToBase64,
};
