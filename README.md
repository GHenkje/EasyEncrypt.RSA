<p align="center">
  <b>EasyEncrypt.RSA</b>
  <br/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/version-1.0.1.2-green.svg">
  <img src="https://img.shields.io/badge/build-passing-green.svg">
  <br/>
  <br/>
  <a>Library that makes encrypting and signing with RSA easy. <a/>
  <br/><br/>
</p>
```cs
EasyRSAKey key = EasyRSA.CreateKey(Keysize);//Create key.

//Create RSA classes.
PrivateRSA RSAPrivate = new PrivateRSA(key.PrivateKey);
PublicRSA RSAPublic = new PublicRSA(key.PublicKey);

var encryptedData = RSAPublic.Encrypt(Data);//Encrypting data.
var decryptedData = RSAPrivate.Decrypt(EncryptedData);//Decrypting data.

byte[] signedData = RSAPrivate.Sign(Data);//Sign data.
bool verify = RSAPublic.Verify(Data, signedData);//Verify data.
```
