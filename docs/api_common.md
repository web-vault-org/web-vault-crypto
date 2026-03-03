# API

This file explains how to use the library's API for common functions.

## Table of contents

- [rewriteEncryptionHeader](#rewriteencryptionheader)



## rewriteEncryptionHeader

Changes key, without re-encryption. \
Replaces wrapped key(s) without changing IV and ciphertext. \
Result is base64-encoded string if input was, otherwise Uint8Array.

### Syntax

``` js
import { rewriteEncryptionHeader } from 'web-vault-crypto';

// example 1: replace symmetric key with two public keys
const rewritten = await rewriteEncryptionHeader({
  content: encrypted,
  oldKey: symmetricKey,
  newKey: [rsaPair1.publicKey, rsaPair2.publicKey]
});

// example 2: replace public key with symmetric key
const rewritten = await rewriteEncryptionHeader({
  content: encrypted,
  oldKey: rsaPair1.privateKey,
  newKey: symmetricKey,
  keyIndex: 1
});
```

### Parameters

-   `content` (string | Uint8Array) &minus; data to change the key in
-   `oldKey` (string | Uint8Array) &minus; old key (symmetric key or private key)
-   `newKey` (string[] | Uint8Array) &minus; new key (symmetric key or public key(s))
-   `keyIndex` (number, optional) &minus; 1-based index of corresponding public key \
    example: On encryption three public keys where provided, the private key provided
    on rewrite belongs to the second public key, so provide 2 as keyIndex. \
    default: 1, ignored if old key is symmetric

### Returns

Promise resolving to:
`rewritten data` (string or Uint8Array, depends on what it was before)
