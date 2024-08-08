const {
    findEncyptionKeyInFile,
    hexToBase64,
    xorHexStrings,
    findEncyptionKey,
    xorDecrypt,
    findTextFromFileWithKey,
    repeatingKeyXOR,
} = require("./set-1");

describe('set-1' , () => {
    test('C1: Convert hex to base64', () => {
        const result = hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');

        expect(result).toStrictEqual('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');
    });

    test('C2: Fixed XOR', () => {
        const hexOne = '1c0111001f010100061a024b53535009181c';
        const hexEncryptionKey = '686974207468652062756c6c277320657965';

        const result = xorHexStrings(hexOne, hexEncryptionKey);

        expect(result).toStrictEqual('746865206b696420646f6e277420706c6179');
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

        expect(key).toStrictEqual(53);

        const message = findTextFromFileWithKey(fileName, key);

        expect(message).toBe('Now that the party is jumping\n');
    });

    test('C5: Implement repeating-key XOR', async () => {
        const plainText = `Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal`;
        const key = 'ICE';
        const expected = `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`;

        const result = repeatingKeyXOR(plainText, key);

        expect(result).toStrictEqual(expected);
    });
});
