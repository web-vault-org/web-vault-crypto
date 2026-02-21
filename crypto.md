# Crypto/Security

This file explains how the cryptography is done internally.

## Key generation
Keys are generated, using a cryptographically-secure random number generator.

## Key derivation / Password hashing
Key derivation and password hashing are made...
* if you specified `argon2id` as type or didn't specify any type: using argon2id
  * with following parameters:
    * Iterations: 2
    * Parallelism: 1
    * Memory: 24MiB
  * using [argon2-browser](https://www.npmjs.com/package/argon2-browser) as library
* if you specified `pbkf2` as type:
    * 1 Million iterations
    * Using [native web crypto api](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) as library

## Key wrapping/unwrapping
Key wrapping/unwrapping (key encryption/decryption) is made, using aes-key-wrap. \
All given keys are wrapped separately.

## encryption/decryption
Encryption/decryption is made, using AES-256-GCM

The encryption process goes as follows:
* Generate new random key (256 bit)
* Use generated key to encrypt content via AES-GCM
* Wrap generated key with given key
* Concatenate: wrapped key | encrypted content

The decryption process goes as follows:
* extract wrapped key and encrypted content
* Unwrap generated key with given key
* Use generated key to decrypt content via AES-GCM

## Sign/Verify
Sign/Verify is made, using hmac, using SHA256

## Libraries
For argon2id, [argon2-browser](https://www.npmjs.com/package/argon2-browser) is used.

For everything else [native web crypto api](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) is used.
