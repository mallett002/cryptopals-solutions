const { hexToBase64 } = require("./set-1");

describe('set-1', () => {
    test('C1: Convert hex to base64', () => {
        const result = hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d');

        expect(result).toStrictEqual('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');
    });
});
