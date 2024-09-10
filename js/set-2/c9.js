function getPaddedPlainText(plainText, blockSize) {
    const EOT = 4;
    let plainTextBytes = Buffer.from(plainText, 'utf-8');


    while (plainTextBytes.length < blockSize) {
        plainTextBytes = Buffer.concat([plainTextBytes, Buffer.from(String.fromCharCode(EOT), 'utf-8')]);

    }

    return plainTextBytes.toString('utf-8');
}

module.exports = {
    getPaddedPlainText,
}