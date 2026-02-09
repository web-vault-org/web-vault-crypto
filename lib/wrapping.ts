import { getCrypto } from '@/crypto';
import { importKey, mergeUint8Array, splitByLengths } from '@/util';
import { decode, encode as encodeBase64 } from '@/base64';

const wrapKey = async function ({ keys, kek, encode }: { keys: Uint8Array[]; kek: Uint8Array; encode?: boolean }): Promise<Uint8Array | string> {
  const crypto = await getCrypto();
  const key = mergeUint8Array(keys);
  const keyMaterial = await importKey(key, 'AES-KW', ['wrapKey']);
  const kekMaterial = await importKey(kek, 'AES-KW', ['wrapKey']);
  const wrapped = await crypto.subtle.wrapKey('raw', keyMaterial, kekMaterial, { name: 'AES-KW' });

  if (encode) {
    return encodeBase64(new Uint8Array(wrapped));
  }
  return new Uint8Array(wrapped);
};

const unwrapKey = async function ({
  wrappedKeys,
  kek,
  length
}: {
  wrappedKeys: Uint8Array | string;
  kek: Uint8Array;
  length?: number[];
}): Promise<Uint8Array[]> {
  const crypto = await getCrypto();
  const kekMaterial = await importKey(kek, 'AES-KW', ['unwrapKey']);
  const wrappedKey = typeof wrappedKeys === 'string' ? decode(wrappedKeys) : wrappedKeys;

  const unwrappedKey = await crypto.subtle.unwrapKey('raw', wrappedKey.buffer, kekMaterial, { name: 'AES-KW' }, { name: 'AES-KW' }, true, [
    'wrapKey',
    'unwrapKey'
  ]);

  const rawKey = await crypto.subtle.exportKey('raw', unwrappedKey);
  const key = new Uint8Array(rawKey);

  return splitByLengths(key, length ?? []);
};

export { wrapKey, unwrapKey };
