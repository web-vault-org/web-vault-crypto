import { getCrypto } from '@/crypto';
import { importKey } from '@/util';
import { decode, encode as encodeBase64 } from '@/base64';

/**
 * wraps/encrypts key
 * @param key - key to wrap/encrypt (length (in bytes) must be 16, 24 or 32 bytes)
 * @param kek - key used to encrypt the keys (length (in bytes) must be 16, 24 or 32 bytes)
 * @param encode - boolean, if wrapped keys should be base64-encoded
 * @returns Promise with wrappedKeys, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const wrapKey = async function ({ key, kek, encode }: { key: Uint8Array; kek: Uint8Array; encode?: boolean }): Promise<Uint8Array | string> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error('Invalid kek length. Must be 16, 24 or 32');
  }

  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('Invalid key length. Must be 16, 24 or 32');
  }

  const crypto = getCrypto();
  const keyMaterial = await importKey(key, 'AES-KW', ['wrapKey'], true);
  const kekMaterial = await importKey(kek, 'AES-KW', ['wrapKey'], true);
  const wrapped = await crypto.subtle.wrapKey('raw', keyMaterial, kekMaterial, { name: 'AES-KW' });

  if (encode) {
    return encodeBase64(new Uint8Array(wrapped));
  }
  return new Uint8Array(wrapped);
};

/**
 * unwraps/decrypts key
 * @param wrappedKey - key to unwrap/decrypt (Uint8Array or base64-encoded string)
 * @param kek - key used to encrypt the keys (length (in bytes) must be 16, 24 or 32 bytes)
 * @returns Promise with unwrapped key (Uint8Array)
 */
const unwrapKey = async function ({
  wrappedKey,
  kek
}: {
  wrappedKey: Uint8Array | string;
  kek: Uint8Array;
  lengths?: number[];
}): Promise<Uint8Array> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error('Invalid kek length. Must be 16, 24 or 32');
  }

  const crypto = getCrypto();
  const kekMaterial = await importKey(kek, 'AES-KW', ['unwrapKey'], true);
  const wrappedKeyDecoded = typeof wrappedKey === 'string' ? decode(wrappedKey) : wrappedKey;

  const unwrappedKey = await crypto.subtle.unwrapKey('raw', wrappedKeyDecoded.buffer, kekMaterial, { name: 'AES-KW' }, { name: 'AES-KW' }, true, [
    'wrapKey',
    'unwrapKey'
  ]);

  const rawKey = await crypto.subtle.exportKey('raw', unwrappedKey);
  return new Uint8Array(rawKey);
};

/**
 * wraps/encrypts keys
 * @param keys - keys to wrap/encrypt (length (in bytes) for each key must be 16, 24 or 32 bytes)
 * @param kek - key used to encrypt the keys (length (in bytes) must be 16, 24 or 32 bytes)
 * @param encode - boolean, if wrapped keys should be base64-encoded
 * @returns Promise with wrappedKeys, as array of base64-encoded strings if `encode` is true, of Uint8Arrays if not
 */
const wrapKeys = async function ({ keys, kek, encode }: { keys: Uint8Array[]; kek: Uint8Array; encode?: boolean }): Promise<(Uint8Array | string)[]> {
  const wrappedKeys: (Uint8Array | string)[] = [];
  for (const key of keys) {
    const wrappedKey = await wrapKey({ key, kek, encode });
    wrappedKeys.push(wrappedKey);
  }
  return wrappedKeys;
};

/**
 * unwraps/decrypts keys
 * @param wrappedKeys - keys to unwrap/decrypt (array of Uint8Arrays or base64-encoded strings)
 * @param kek - key used to encrypt the keys (length (in bytes) must be 16, 24 or 32 bytes)
 * @returns Promise with unwrapped key (array of Uint8Arrays)
 */
const unwrapKeys = async function ({ wrappedKeys, kek }: { wrappedKeys: (Uint8Array | string)[]; kek: Uint8Array }): Promise<Uint8Array[]> {
  const keys: Uint8Array[] = [];
  for (const wrappedKey of wrappedKeys) {
    const key = await unwrapKey({ wrappedKey, kek });
    keys.push(key);
  }
  return keys;
};

export { wrapKey, unwrapKey, wrapKeys, unwrapKeys };
