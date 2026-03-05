# API

This file explains how to use the library's API for asymmetric functions.

## Table of contents

- Key Generation
  - [createSigningKeyPair](#createsigningkeypair)
  - [createEncryptionKeyPair](#createencryptionkeypair)
- Asymmetric Encryption
  - [encryptAsymmetric](#encryptasymmetric)
  - [decryptAsymmetric](#decryptasymmetric)
- Digital Signatures
  - [signAsymmetric](#signasymmetric)
  - [verifyAsymmetric](#verifyasymmetric)
- Private Key Wrapping
  - [wrapPrivateSigningKey](#wrapprivatesigningkey)
  - [unwrapPrivateSigningKey](#unwrapprivatesigningkey)
  - [wrapPrivateEncryptionKey](#wrapprivateencryptionkey)
  - [unwrapPrivateEncryptionKey](#unwrapprivateencryptionkey)



## createSigningKeyPair

Creates an Ed25519 public/private key pair for signing and verifying.

### Syntax

``` js
import { createSigningKeyPair } from 'web-vault-crypto';

const keyPair = await createSigningKeyPair();
```

### Parameters

This function does not require parameters.

### Returns

Promise resolving to:
-   `publicKey` (string, PEM encoded)
-   `privateKey` (string, PEM encoded)

## createEncryptionKeyPair

Creates an RSA-OAEP public/private key pair for encryption and
decryption.

### Syntax

``` js
import { createEncryptionKeyPair } from 'web-vault-crypto';

const keyPair = await createEncryptionKeyPair();
```

### Parameters

This function does not require parameters.

### Returns

Promise resolving to:
-   `publicKey` (string, PEM encoded)
-   `privateKey` (string, PEM encoded)

## encryptAsymmetric

Encrypts content using hybrid encryption (RSA-OAEP + AES-GCM).

### Syntax

``` js
import { encryptAsymmetric } from 'web-vault-crypto';

const encrypted = await encryptAsymmetric({
  content: 'top secret',
  publicKeys: [publicKey],
  encode: true,
  additionalData: ['context']
});
```

### Parameters

-   `content` (string \| Uint8Array) &minus; plaintext
-   `publicKeys` (string\[\]) &minus; array of RSA public keys (PEM)
-   `encode` (boolean, optional) &minus; if true, returns base64 string
    (default: false)
-   `additionalData` (string\[\], optional) &minus; additional authenticated
    data (AAD)

### Returns

Promise resolving to:
-   base64 `string` if `encode = true`
-   `Uint8Array` if `encode = false`

## decryptAsymmetric

Decrypts content encrypted with encryptAsymmetric.

### Syntax

``` js
import { decryptAsymmetric } from 'web-vault-crypto';

const decrypted = await decryptAsymmetric({
  content: encrypted,
  privateKey,
  keyIndex: 1,
  asString: true,
  additionalData: ['context']
});
```

### Parameters

-   `content` (string \| Uint8Array) &minus; ciphertext
-   `privateKey` (string) &minus; RSA private key (PEM)
-   `keyIndex` (number) &minus; 1-based index of corresponding public key \
    example: On encryption three public keys where provided, the private key provided
    on decryption belongs to the second public key, so provide 2 as keyIndex
-   `asString` (boolean, optional) &minus; return plaintext as string
    (default: false)
-   `additionalData` (string\[\], optional) &minus; must match encryption
    AAD

### Returns

Promise resolving to:
-   `string` if `asString = true`
-   `Uint8Array` otherwise

## signAsymmetric

Signs an object using Ed25519.

### Syntax

``` js
import { signAsymmetric } from 'web-vault-crypto';

const signature = await signAsymmetric({
  data: { id: 1 },
  privateSigningKey,
  exclude: ['timestamp']
});
```

### Parameters

-   `data` (object) &minus; object to sign
-   `privateSigningKey` (string) &minus; Ed25519 private key (PEM)
-   `exclude` (string\[\], optional) &minus; property names to exclude

### Returns

Promise resolving to:
-   base64-encoded signature (`string`)

## verifyAsymmetric

Verifies an object signature.

### Syntax

``` js
import { verifyAsymmetric } from 'web-vault-crypto';

const isValid = await verifyAsymmetric({
  data,
  publicSigningKey,
  signature,
  exclude: ['timestamp']
});
```

### Parameters

-   `data` (object) &minus; object to verify
-   `publicSigningKey` (string) &minus; Ed25519 public key (PEM)
-   `signature` (string) &minus; base64 signature
-   `exclude` (string\[\], optional) &minus; excluded properties

### Returns

Promise resolving to:
-   `boolean` indicating authenticity and integrity

## wrapPrivateSigningKey

Encrypts an Ed25519 private key using AES.

### Syntax

``` js
import { wrapPrivateSigningKey } from 'web-vault-crypto';

const wrapped = await wrapPrivateSigningKey({
  privateSigningKey,
  key,
  encode: true
});
```

### Parameters

-   `privateSigningKey` (string) &minus; PEM encoded Ed25519 private key
-   `key` (Uint8Array) &minus; 16, 24 or 32 byte AES key
-   `encode` (boolean, optional) &minus; return base64 string (default:
    false)

### Returns

Promise resolving to:

-   base64 `string` if `encode = true`
-   `Uint8Array` otherwise

## unwrapPrivateSigningKey

Decrypts wrapped Ed25519 private key.

### Syntax

``` js
import { unwrapPrivateSigningKey } from 'web-vault-crypto';

const unwrapped = await unwrapPrivateSigningKey({
  wrappedPrivateSigningKey,
  key
});
```

### Parameters

-   `wrappedPrivateSigningKey` (string \| Uint8Array)
-   `key` (Uint8Array) &minus; 16, 24 or 32 byte AES key

### Returns

Promise resolving to:

-   `string` containing the private key (PEM)

## wrapPrivateEncryptionKey

Encrypts RSA private key using AES.

### Syntax

``` js
import { wrapPrivateEncryptionKey } from 'web-vault-crypto';

const wrapped = await wrapPrivateEncryptionKey({
  privateEncryptionKey,
  key,
  encode: true
});
```

### Parameters

-   `privateEncryptionKey` (string) &minus; PEM encoded RSA private key
-   `key` (Uint8Array) &minus; 16, 24 or 32 byte AES key
-   `encode` (boolean, optional) &minus; if true wrapped key will be base64-encoded

### Returns

Promise resolving to:

-   base64 `string` if `encode = true`
-   `Uint8Array` otherwise

## unwrapPrivateEncryptionKey

Decrypts RSA private key.

### Syntax

``` js
import { unwrapPrivateEncryptionKey } from 'web-vault-crypto';

const unwrapped = await unwrapPrivateEncryptionKey({
  wrappedPrivateEncryptionKey,
  key
});
```

### Parameters

-   `wrappedPrivateEncryptionKey` (string \| Uint8Array)
-   `key` (Uint8Array) &minus; 16, 24 or 32 byte AES key

### Returns

Promise resolving to:

-   `string` containing the private key (PEM)
