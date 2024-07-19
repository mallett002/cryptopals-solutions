const { hexToBase64, xorHexStrings } = require("./set-1");

describe('set-1', () => {
    test('C1: Convert hex to base64', () => {
        const result = hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');

        expect(result).toStrictEqual('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');
    });

    test('C2: Fixed XOR', () => {
        const source = '1c0111001f010100061a024b53535009181c';
        const comparator = '686974207468652062756c6c277320657965';

        const result = xorHexStrings(source, comparator);

        expect(result).toStrictEqual('746865206b696420646f6e277420706c6179');
    });
});
