const {
    findEncyptionKeyInFile,
    hexToBase64,
    xorHexStrings,
    findEncyptionKey,
    xorDecrypt,
} = require("./set-1");

describe('set-1' , () => {
    test('C1: Convert hex to base64', () => {
        const result = hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');

        expect(result).toStrictEqual('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');
    });

    test('C2: Fixed XOR', () => {
        const hexOne = '1c0111001f010100061a024b53535009181c';
        const hexEncryptionKey = '686974207468652062756c6c277320657965';
        const expectedResult = '746865206b696420646f6e277420706c6179';

        const result = xorHexStrings(hexOne, hexEncryptionKey);

        expect(result).toStrictEqual(expectedResult);
    });

    test('C3: Single-byte XOR cipher', () => {
        const hexInput = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';

        const {key} = findEncyptionKey(hexInput);

        expect(key).toStrictEqual(88);
        expect(xorDecrypt(hexInput, key)).toStrictEqual("Cooking MC's like a pound of bacon");
    });

    test('C4: Detect single-character XOR', async () => {
        const fileName = '4.txt';

        const key = await findEncyptionKeyInFile(fileName);

        expect(key).toStrictEqual(88);
    });
});
