import { importKey, splitByLengths } from '@/util';
import { encode as encodeBase64, decode as decodeBase64 } from '@/base64';
import { getCrypto } from '@/crypto';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const toUint8Array = function (data: string | Uint8Array): Uint8Array {
  return typeof data === 'string' ? encoder.encode(data) : data;
};

const concat = function (...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
};

const encodeAAD = function (additionalData?: string[]): Uint8Array | undefined {
  if (!additionalData || additionalData.length === 0) return undefined;
  return encoder.encode(additionalData.join('\u0000'));
};

/**
 * encrypts a string or a Uint8Array
 * @param content - plaintext as string or Uint8Array
 * @param key - key as Uint8Array
 * @param encode - boolean, if plaintext should be base64-encoded
 * @param additionalData - array of strings, with additional Data for integrity and authenticity checks
 * @returns Promise with ciphertext, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const encrypt = async function ({
  content,
  key,
  encode,
  additionalData
}: {
  content: string | Uint8Array;
  key: Uint8Array;
  encode?: boolean;
  additionalData?: string[];
}): Promise<Uint8Array | string> {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('Invalid key length. Must be 16, 24 or 32');
  }

  const crypto = getCrypto();

  const plaintext = toUint8Array(content);
  const aad = encodeAAD(additionalData);
  const contentKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: key.length * 8 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, contentKey, plaintext));

  const kek = await importKey(key, 'AES-KW', ['wrapKey']);
  const wrappedKey = new Uint8Array(await crypto.subtle.wrapKey('raw', contentKey, kek, { name: 'AES-KW' }));

  const result = concat(wrappedKey, iv, ciphertext);
  return encode ? encodeBase64(result) : result;
};

/**
 * decrypts a string or a Uint8Array
 * @param content - ciphertext as string or Uint8Array
 * @param key - key as Uint8Array
 * @param asString - boolean, if plaintext should be returned as string
 * @param additionalData - array of strings, with additional Data for integrity and authenticity checks
 * @returns Promise with plaintext, as string if `asString` is true, as Uint8Array if not
 */
const decrypt = async function ({
  content,
  key,
  asString,
  additionalData
}: {
  content: string | Uint8Array;
  key: Uint8Array;
  asString?: boolean;
  additionalData?: string[];
}): Promise<Uint8Array | string> {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('Invalid key length. Must be 16, 24 or 32');
  }

  const crypto = getCrypto();

  const data = typeof content === 'string' ? decodeBase64(content) : content;
  const aad = encodeAAD(additionalData);
  const [wrappedKey, iv, ciphertext] = splitByLengths(data, [key.length + 8, 12]);

  const kek = await importKey(key, 'AES-KW', ['unwrapKey']);
  const contentKey = await crypto.subtle.unwrapKey('raw', wrappedKey.buffer, kek, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, false, [
    'decrypt'
  ]);

  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, contentKey, ciphertext));

  return asString ? decoder.decode(plaintext) : plaintext;
};

export { encrypt, decrypt };
