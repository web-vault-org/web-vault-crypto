import { getCrypto } from '@/crypto';
import { pemToArrayBuffer, rsaOaepParams, validatePrivateEncryptionKey, validatePublicEncryptionKey } from '@/asymmetric/util';
import { decode as decodeBase64, encode as encodeBase64 } from '@/base64';
import { importKey, splitByLengths } from '@/util';
import { encodeAAD, encryptWithRandomKeyUsingAesGcm } from '@/symmetric/encryption';

const crypto = getCrypto();
const decoder = new TextDecoder();
const usages: KeyUsage[] = ['encrypt', 'decrypt'];

const concatUint8Arrays = function (arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
};

const wrapKeyWithPublicKey = async function (key: Uint8Array, publicKey: string): Promise<Uint8Array> {
  validatePublicEncryptionKey(publicKey);
  const publicKeyImported = await crypto.subtle.importKey('spki', pemToArrayBuffer(publicKey), rsaOaepParams, true, ['wrapKey']);
  const symmetricKeyImported = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const wrappedKey = await crypto.subtle.wrapKey('raw', symmetricKeyImported, publicKeyImported, { name: 'RSA-OAEP' });
  return new Uint8Array(wrappedKey);
};

const unwrapKeyWithPrivateKey = async function (wrappedKey: Uint8Array, privateKey: string): Promise<Uint8Array> {
  validatePrivateEncryptionKey(privateKey);
  const privateKeyImported = await crypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKey), rsaOaepParams, true, ['unwrapKey']);
  const unwrappedKey = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey.buffer,
    privateKeyImported,
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM' },
    true,
    usages
  );
  const unwrappedKeyExported = await crypto.subtle.exportKey('raw', unwrappedKey);
  return new Uint8Array(unwrappedKeyExported);
};

/**
 * encrypts a string or a Uint8Array with one or more public keys (RSA-OAEP & AES-GCM)
 * @param content - the content to be encrypted
 * @param publicKeys - array of strings, with public keys (PEM)
 * @param encode - boolean, if plaintext should be base64-encoded
 * @param additionalData array of strings, with additional Data for integrity and authenticity checks
 * @returns Promise with ciphertext, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const encrypt = async function ({
  content,
  publicKeys,
  encode,
  additionalData
}: {
  content: string | Uint8Array;
  publicKeys: string[];
  encode?: boolean;
  additionalData?: string[];
}): Promise<string | Uint8Array> {
  const [contentKey, iv, ciphertext] = await encryptWithRandomKeyUsingAesGcm(content, 256, additionalData);

  const key = await crypto.subtle.exportKey('raw', contentKey);
  const wrappedKeys: Uint8Array[] = [];
  for (const publicKey of publicKeys) {
    const wrapped = await wrapKeyWithPublicKey(new Uint8Array(key), publicKey);
    wrappedKeys.push(wrapped);
  }

  const result = concatUint8Arrays([new Uint8Array([publicKeys.length]), ...wrappedKeys, iv, ciphertext]);
  return encode ? encodeBase64(result) : result;
};

/**
 * decrypts a string or a Uint8Array with a private key (RSA-OAEP & AES-GCM)
 * @param content - ciphertext as string or Uint8Array
 * @param privateKey - private key (PEM)
 * @param keyIndex - index, determining which public key the private key belongs to.
 * example: On encryption three public keys where provided, the private key provided on decryption belongs to the second public key, so provide 2 as keyIndex
 * (keyIndex is 1-based)
 * @param asString - boolean, if plaintext should be returned as string
 * @param additionalData - array of strings, with additional Data for integrity and authenticity checks
 * @returns Promise with plaintext, as string if `asString` is true, as Uint8Array if not
 */
const decrypt = async function ({
  content,
  privateKey,
  keyIndex,
  asString,
  additionalData
}: {
  content: string | Uint8Array;
  privateKey: string;
  keyIndex: number;
  asString?: boolean;
  additionalData?: string[];
}): Promise<Uint8Array | string> {
  const [contentKey, iv, ciphertext] = await extract(content, privateKey, keyIndex);
  const aad = encodeAAD(additionalData);

  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, contentKey, ciphertext));
  return asString ? decoder.decode(plaintext) : plaintext;
};

const extract = async function (content: string | Uint8Array, privateKey: string, keyIndex: number): Promise<[CryptoKey, Uint8Array, Uint8Array]> {
  const data = typeof content === 'string' ? decodeBase64(content) : content;
  const length = data.at(0) ?? 0;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_, wrappedKeys, iv, ciphertext] = splitByLengths(data, [1, length * 256, 12]);

  const start = 256 * (keyIndex - 1);
  const wrappedKey = wrappedKeys.slice(start, start + 256);
  const key = await unwrapKeyWithPrivateKey(wrappedKey, privateKey);
  const contentKey = await importKey(key, 'AES-GCM', usages, true);
  return [contentKey, iv, ciphertext];
};

const rewrite = async function (contentKey: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array, publicKeys: string[]): Promise<Uint8Array> {
  const key = await crypto.subtle.exportKey('raw', contentKey);
  const wrappedKeys: Uint8Array[] = [];
  for (const publicKey of publicKeys) {
    const wrapped = await wrapKeyWithPublicKey(new Uint8Array(key), publicKey);
    wrappedKeys.push(wrapped);
  }
  return concatUint8Arrays([new Uint8Array([publicKeys.length]), ...wrappedKeys, iv, ciphertext]);
};

export { encrypt, decrypt, extract, rewrite };
