# Asymmetric Encryption with RSA for Titanium (Android)

iOS Version: https://github.com/moritzknecht/TiRSA

## RSA Example:

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


## AES Example:

```javascript
let crypt = require("miga.ticrypt");
let aesCrypto = crypt.createCryptoAES();
let aesKey = aesCrypto.generateKey();
console.log("AES key: " + aesKey);
let txt = aesCrypto.crypt(aesKey, "test text");
console.log("AES Encode: " + txt);

let txt_decode =  aesCrypto.decrypt(txt, aesKey);
console.log("AES Decode: " + txt_decode);
```

## Contributions:
* blacktiago (https://github.com/blacktiago)
