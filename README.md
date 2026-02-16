# web-vault-crypto

[![NPM](https://nodei.co/npm/web-vault-crypto.svg?style=shields&data=n,v,u,d,s&color=blue)](https://nodei.co/npm/web-vault-crypto/) \
[![QA-Main](https://github.com/web-vault-org/web-vault-crypto/actions/workflows/qa_main.yml/badge.svg?branch=main)](https://github.com/web-vault-org/web-vault-crypto/actions/workflows/qa_main.yml)

Crypto-Library for e2e encrypted web vaults,
using [native web crypto api](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
and [argon2-browser](https://www.npmjs.com/package/argon2-browser),
written in typescript, easy to use.

## Introduction
This package provides easy to use crypto-functions, suitable for web-vaults (examples: password-safes, e2e encrypted video collections).

Used crypto-libraries:
* [argon2-browser](https://www.npmjs.com/package/argon2-browser) for password-based-key-derivation and password hashing,
  using argon2id
* [native web crypto api](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for everything else

## Features
* key generation
* password-based key derivation &minus; argon2id
* password hashing &minus; argon2id / PBKDF2
* key wrapping and unwrapping &minus; aeskeywrap
* encryption and decryption &minus; `AEAD` using `AES-256-GCM`
* signing and verification &minus; using `hmac`

## Usage

### npm

Install:
```bash
npm install web-vault-crypto
```

Import:
```js

// Replace createKey with a comma-separated list of the functions, you need
import { createKey } from 'web-vault-crypto';
const key = await createKey({ sizeInBytes: 32 });

// or import all functions
import webVaultCrypto from 'web-vault-crypto';
const key = await webVaultCrypto.createKey({ sizeInBytes: 32 });
```

### Browser

```html
<!-- Load the file from jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/web-vault-crypto@latest/dist/web-vault-crypto.js"></script>

<!-- or load the file from unpkg -->
<script src="https://unpkg.com/web-vault-crypto@latest/dist/web-vault-crypto.js"></script>

<!-- or download the file and host it yourself -->
<script src="/js/web-vault-crypto.js"></script>

<script>
// Replace createKey with a comma-separated list of the functions, you need
const { createKey } = webVaultCrypto;
const key = await createKey({ sizeInBytes: 32 });

// or use functions directly
const key = await webVaultCrypto.createKey({ sizeInBytes: 32 });
</script>
```

## API
Read [API Documentation](./api.md) to see how to use the functions

## Crypto/Security
Read [Security Concept](./crypto.md) to see the crypto/security concepts

## License
This project is licensed under the [MIT License](./LICENSE.txt)
