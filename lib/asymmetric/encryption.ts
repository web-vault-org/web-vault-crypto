import { getCrypto } from '@/crypto';
import { pemToArrayBuffer, rsaOaepParams, validatePrivateEncryptionKey, validatePublicEncryptionKey } from '@/asymmetric/util';
import { decode as decodeBase64, encode as encodeBase64 } from '@/base64';
import { importKey, splitByLengths } from '@/util';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const usages: KeyUsage[] = ['encrypt', 'decrypt'];

const toUint8Array = function (data: string | Uint8Array): Uint8Array {
  return typeof data === 'string' ? encoder.encode(data) : data;
};

const encodeAAD = function (additionalData?: string[]): Uint8Array | undefined {
  if (!additionalData || additionalData.length === 0) return undefined;
  return encoder.encode(additionalData.join('\u0000'));
};

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
  const crypto = getCrypto();
  const publicKeyImported = await crypto.subtle.importKey('spki', pemToArrayBuffer(publicKey), rsaOaepParams, true, ['wrapKey']);
  const symmetricKeyImported = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const wrappedKey = await crypto.subtle.wrapKey('raw', symmetricKeyImported, publicKeyImported, { name: 'RSA-OAEP' });
  return new Uint8Array(wrappedKey);
};

const unwrapKeyWithPrivateKey = async function (wrappedKey: Uint8Array, privateKey: string): Promise<Uint8Array> {
  validatePrivateEncryptionKey(privateKey);
  const crypto = getCrypto();
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
  const crypto = getCrypto();
  const plaintext = toUint8Array(content);
  const aad = encodeAAD(additionalData);
  const contentKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const key = await crypto.subtle.exportKey('raw', contentKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, contentKey, plaintext));

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
 * example: On encryption three public keys where provided, the private key provided on decryption belong to the second public key, so provide 2 as keyIndex
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
  const crypto = getCrypto();
  const data = typeof content === 'string' ? decodeBase64(content) : content;
  const aad = encodeAAD(additionalData);
  const length = data.at(0) ?? 0;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_, wrappedKeys, iv, ciphertext] = splitByLengths(data, [1, length * 256, 12]);

  const start = 256 * (keyIndex - 1);
  const wrappedKey = wrappedKeys.slice(start, start + 256);
  const key = await unwrapKeyWithPrivateKey(wrappedKey, privateKey);
  const contentKey = await importKey(key, 'AES-GCM', usages, true);

  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, contentKey, ciphertext));
  return asString ? decoder.decode(plaintext) : plaintext;
};

export { encrypt, decrypt };
