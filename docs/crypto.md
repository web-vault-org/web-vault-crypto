# Crypto/Security

This file explains how the cryptography is done internally.

## Key generation
Symmetric Keys are generated, using a cryptographically-secure random number generator.

Asymmetric keys are generated, using
`Ed25519` for signing keys and `RSA-OAEP` for encryption keys

## Key derivation / Password hashing
Key derivation and password hashing are made...
* if you specified `argon2id` as type or didn't specify any type: using argon2id
  * with following parameters:
    * Iterations: 2
    * Parallelism: 1
    * Memory: 24MiB
  * using argon2id
* if you specified `pbkf2` as type:
    * 1 Million iterations
    * Using `PBKDF2`

## Key wrapping/unwrapping
Symmetric key wrapping/unwrapping (key encryption/decryption) is made, using aes-key-wrap. \
All given keys are wrapped separately.

Asymmetric key wrapping/unwrapping (key encryption/decryption) is made, using AES-GCM.

## encryption/decryption

### Symmetric
Encryption/decryption is made, using aes-key-wrap and AES-256-GCM

The encryption process goes as follows:
* Generate new random key (256 bit)
* Generate new random IV (96 bit)
* Use generated key to encrypt content via AES-GCM
* Wrap generated key with given key
* Concatenate: wrapped key | IV | encrypted content

The decryption process goes as follows:
* extract wrapped key, IV and encrypted content
* Unwrap generated key with given key
* Use unwrapped key to decrypt content via AES-GCM

### Asymmetric

Encryption/decryption is made, using RSA-OAEP and AES-256-GCM

The encryption process goes as follows:
* Generate new random key (256 bit)
* Generate new random IV (96 bit)
* Use generated key to encrypt content via AES-GCM
* Wrap generated key for/with each provided public key
* Concatenate: amount of provided public keys (1 byte) | wrapped keys | IV | encrypted content

The decryption process goes as follows:
* extract wrapped key, IV and encrypted content
* Unwrap wrapped key with private key
* Use unwrapped key to decrypt content via AES-GCM

### Rewriting of keys
For the `rewriteEncryptionHeader` function,
the extracting, unwrapping, wrapping and concatenating steps are re-used, without touching IV or ciphertext.

## Sign/Verify
Symmetric Sign/Verify is made, using hmac, using SHA256

Asymmetric Sign/Verify is made, using Ed25519, using SHA256

## Libraries
For argon2id, [argon2-browser](https://www.npmjs.com/package/argon2-browser) is used.

For everything else [native web crypto api](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) is used.
