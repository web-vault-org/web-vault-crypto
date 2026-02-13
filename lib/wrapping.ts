import { getCrypto } from '@/crypto';
import { importKey, mergeUint8Array, splitByLengths } from '@/util';
import { decode, encode as encodeBase64 } from '@/base64';

/**
 * wraps/encrypts keys
 * @param keys - keys to wrap/encrypt (length (in bytes) for each key must be multiple of 8)
 * @param kek - key used to encrypt the keys
 * @param encode - boolean, if wrapped keys should be base64-encoded
 * @returns Promise with wrappedKeys, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const wrapKeys = async function ({ keys, kek, encode }: { keys: Uint8Array[]; kek: Uint8Array; encode?: boolean }): Promise<Uint8Array | string> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error('Invalid kek length. Must be 16, 24 or 32');
  }
  const keysLength = keys.reduce((a, b) => a + b.length, 0);
  if (keysLength <= 0 || keysLength % 8 > 0) {
    throw new Error('Invalid keys length. Must be multiple of 8 bytes');
  }

  const crypto = getCrypto();
  const key = mergeUint8Array(keys);
  const keyMaterial = await importKey(key, 'AES-KW', ['wrapKey']);
  const kekMaterial = await importKey(kek, 'AES-KW', ['wrapKey']);
  const wrapped = await crypto.subtle.wrapKey('raw', keyMaterial, kekMaterial, { name: 'AES-KW' });

  if (encode) {
    return encodeBase64(new Uint8Array(wrapped));
  }
  return new Uint8Array(wrapped);
};

/**
 * unwraps/decrypts keys
 * @param wrappedKeys - keys to unwrap/decrypt
 * @param kek - key used to encrypt the keys
 * @param lengths - An array of `number`s, providing the lengths of the unwrapped keys
 * @returns Promise with an array of unwrapped keys
 */
const unwrapKeys = async function ({
  wrappedKeys,
  kek,
  lengths
}: {
  wrappedKeys: Uint8Array | string;
  kek: Uint8Array;
  lengths?: number[];
}): Promise<Uint8Array[]> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error('Invalid kek length. Must be 16, 24 or 32');
  }

  const crypto = getCrypto();
  const kekMaterial = await importKey(kek, 'AES-KW', ['unwrapKey']);
  const wrappedKey = typeof wrappedKeys === 'string' ? decode(wrappedKeys) : wrappedKeys;

  const unwrappedKey = await crypto.subtle.unwrapKey('raw', wrappedKey.buffer, kekMaterial, { name: 'AES-KW' }, { name: 'AES-KW' }, true, [
    'wrapKey',
    'unwrapKey'
  ]);

  const rawKey = await crypto.subtle.exportKey('raw', unwrappedKey);
  const key = new Uint8Array(rawKey);

  return splitByLengths(key, lengths ?? []);
};

export { wrapKeys, unwrapKeys };
