# Asymmetric Encryption with RSA for Titanium (Android)

iOS Version: https://github.com/moritzknecht/TiRSA

## Example:

```javascript
var crypt = require("miga.ticrypt");
var keypair = crypt.generateKeyPair();

console.log("Pub: " + keypair.publicKey);
console.log("Priv: " + keypair.privateKey);

var txt = crypt.encode({
    plainText: "test text",
    publicKey: keypair.publicKey
});
console.log("Encode: " + txt);

var txt_decode = crypt.decode({
    cipherText: txt,
    privateKey: keypair.privateKey
});

console.log("Decode: " + txt_decode);

$.index.open();

```
