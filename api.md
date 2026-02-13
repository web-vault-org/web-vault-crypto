# API

This file explains how to use the library's API.

## Key generation
To create a random key, use the function `createKey`, providing the key length in bytes.

### Syntax
```js
import { createKey } from 'web-vault-crypto';
const key = await createKey({ sizeInBytes: 32 });
```

### Parameters

#### sizeInBytes
A `number` providing the desired key length in bytes. The example generates a key with 32 bytes.

### Return value
A Promise that fulfills with the desired key as `Uint8Array`

## Key derivation
To derive a key from a password, use the function `derivePasswordKey`, providing the password, the key length in bytes and optionally a salt.

### Syntax
```js
import { derivePasswordKey } from 'web-vault-crypto';

// using given salt
const [_, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 32, salt: yourGivenSalt });

// use new random salt
const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 32 });
```

### Parameters

#### password
A `string` providing the given password.

#### sizeInBytes
A `number` providing the desired key length in bytes. The example derives a key with 32 bytes.

### salt (optional)
A `string` providing a given salt. If not provided a new random salt will be used.

### Return value
A Promise that fulfills with an array containing
* The given or newly generated salt as `string`
* The key as `Uint8Array`

## Password-Hashing
To hash a password, use the function `hashPassword`, providing the password, the hash length in bytes and optionally a salt.

### Syntax
```js
import { hashPassword } from 'web-vault-crypto';

// using given salt
const [_, hash] = await hashPassword({ password: 'p8ssw0rd!', sizeInBytes: 32, salt: yourGivenSalt });

// use new random salt
const [salt, hash] = await hashPassword({ password: 'p8ssw0rd!', sizeInBytes: 32 });
```

### Parameters

#### password
A `string` providing the given password.

#### sizeInBytes
A `number` providing the desired hash length in bytes. The example creates a 32 bytes hash.

### salt (optional)
A `string` providing a given salt. If not provided a new random salt will be used.

### Return value
A Promise that fulfills with an array containing
* The given or newly generated salt as `string`
* The hash as base64-encoded `string`

## Wrap keys
To wrap keys (the secure way to encrypt a key with another key), use the function `wrapKeys`, providing the keys to wrap,
the wrapping-key and optionally an encode-toggle

### Syntax
```js
import { wrapKeys } from 'web-vault-crypto';

// with base64Encoding
const wrappedAndbase64Encoded = await wrapKeys({ keys: [key1, key2], kek: keyToEncryptKeys, encode: true });

// without encoding
const wrappedAsUintArray = await wrapKeys({ keys: [key1, key2], kek: keyToEncryptKeys });
```

### Parameters

#### keys
An array of `Uint8Array`s providing the keys you want to wrap/encrypt. \
Length (in bytes) for each key must be multiple of 8.

#### kek
A `Uint8Array` providing key-encryption-key

#### encode (optional)
A `boolean`, stating if wrapped keys should be base64-encoded. \
Default: `false`

### Return value
A Promise that fulfills with...
* If `encoded` is `true`: wrapped keys as base64-encoded `string`
* If `encoded` is `false`: wrapped keys as `Uint8Array`

### Notice
A key wrapped as one key can be unwrapped as two or more keys later. So wrapping number must not be equal to unwrap number.

## Unwrap keys
To unwrap keys (the secure way to decrypt a key with another key), use the function `unwrapKeys`, providing the keys to unwrap
and the wrapping-key and optionally the key lengths

### Syntax
```js
import { unwrapKeys } from 'web-vault-crypto';

const unwrapped = await unwrapKeys({ wrappedKey: wrapped, kek: keyToEncryptKeys, lengths: [64] });
```

### Parameters

#### keys
A `Uint8Array` or a base64-encoded `string`, providing the wrapped keys.

#### kek
A `Uint8Array` providing key-encryption-key

#### lengths (optionally)
An array of `number`s, providing the lengths of the unwrapped keys. \
This parameter controls, how the unwrapped key will be split into multiple keys.
* Not provided or empty: No splitting, one key
* If provided: key will be split according to lengths \
  Example:
  * wrapped keys length: 128
  * provided lengths: [64, 32]
  * split key lengths: 64, 32, remaining (32)

### Return value
A Promise that fulfills with an array of `Uint8Array`s, providing the unwrapped keys.

### Notice
A key wrapped as one key can be unwrapped as two or more keys later. So wrapping number must not be equal to unwrap number.

## Encryption
To encrypt a string or a Uint8Array, use the function `encrypt`,
providing the plaintext, the key, optionally an encode-toggle and optionally additionalData

### Syntax

```js
import { encrypt } from 'web-vault-crypto';

// string to base64-encoded-string
const encryptedString = await encrypt({ content: 'top secret!', key: encryptionKey, encode: true });

// string to Uint8Array
const encryptedString = await encrypt({ content: 'top secret!', key: encryptionKey });

// Uint8Array to base64-encoded-string
const encrypted = await encrypt({ content: plaintext, key: encryptionKey, encode: true });

// Uint8Array to Uint8Array, using additionl data for integrety checks
const encrypted = await encrypt({ content: plaintext, key: encryptionKey, additionalData: ['someId'] });
```

### Parameters

#### content
A `string` or `Uint8Array`, providing the plaintext

#### key
A `Uint8Array`, providing the key

#### encode (optional)
A `boolean`, stating if plaintext should be base64-encoded. \
Default: `false`

#### additionalData (optional)
An array of `string`s, providing additional data for integrity checks. \
Example use case: If you encrypt a file content, you can provide filename and formatted date as additional data. \
The example above uses an ID.

### Return value
A Promise that fulfills with...
* If `encode` is `true`: an ase64-encoded `string`, providing the ciphertext
* If `encode` is `false`: a `Uint8Array`, providing the ciphertext

### Notice
The used algorithm also provides authenticity and integrity checks, so you don't need to sign, using hmac.

## Decryption
To decrypt a string or a Uint8Array, use the function `decrypt`,
providing the ciphertext, optionally an asString-toggle and optionally additionalData

### Syntax

```js
import { decrypt } from 'web-vault-crypto';

// string to base64-encoded-string
const decryptedString = await decrypt({ content: 'ZHVtbXlCYXNlNjRFeGFtcGxlVmFsdWU=', key: encryptionKey, asString: true });

// string to Uint8Array
const decryptedString = await decrypt({ content: 'ZHVtbXlCYXNlNjRFeGFtcGxlVmFsdWU=', key: encryptionKey });

// Uint8Array to base64-encoded-string
const decrypted = await decrypt({ content: ciphertext, key: encryptionKey, asString: true });

// Uint8Array to Uint8Array, using addiotional data
const decrypted = await decrypt({ content: ciphertext, key: encryptionKey, additionalData: ['someId'] });
```

### Parameters

#### content
A `string` or `Uint8Array`, providing the ciphertext

#### key
A `Uint8Array`, providing the key

#### asString (optional)
A `boolean`, stating if result should be returned as string. \
Default: `false`

#### additionalData (optional)
An array of `string`s, providing additional data for integrity checks. \
Example use case: If you decrypt a file content, you can provide filename and formatted date as additional data. \
The example above uses an ID.

### Return value
A Promise that fulfills with...
* If `asString` is `true`: a `string`, providing the plaintext
* If `asString` is `false`: a `Uint8Array`, providing the plaintext

### Notice
The used algorithm also provides authenticity and integrity checks, so you don't need to verify, using hmac.

## Sign
To sign an object using hmac, use the function `hmac`,
providing the object, the hashing key and optionally en exclude-list.

### Syntax

```js
import { sign } from 'web-vault-crypto';

// whole object
const data = { a: 1, b: 2, c: 'someExampleValue' };
const signature = await sign({ data, key: signingKey });

// with excludes
const data = { a: 1, b: 2, c: 'someExampleValue' };
const signature = await sign({ data, key: signingKey, exclude: ['b', 'c'] });
```

### Parameters

#### data
An `object`, providing the data to sign

#### key
A `Uint8Array`, providing the signing key

#### exclude (optionally)
An array of `string`s, providing a list of properties to exclude.

### Return value
A Promise that fulfills with a base64-encoded `string`, providing the signature

## Verify
To verify an object using hmac, use the function `verify`,
providing the object, the hashing key, the signature and optionally an exclude-list.

### Syntax

```js
import { verify } from 'web-vault-crypto';

// whole object
const data = { a: 1, b: 2, c: 'someExampleValue' };
const valid = await verify({ data, key: signingKey, signature: 'ZHVtbXlCYXNlNjRFeGFtcGxlVmFsdWU=' });

// with excludes
const data = { a: 1, b: 2, c: 'someExampleValue' };
const valid = await verify({ data, key: signingKey, signature: 'ZHVtbXlCYXNlNjRFeGFtcGxlVmFsdWU=', excludes: ['b', 'c'] });
```

### Parameters

#### data
An `object`, providing the data to verify

#### key
A `Uint8Array`, providing the signing key

#### signature
A base64-encoded `string`, providing the signature

#### exclude (optionally)
An array of `string`s, providing a list of properties to exclude.

### Return value
A Promise that fulfills with a `boolean`, stating if the signature is valid
