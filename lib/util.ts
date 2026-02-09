import { getCrypto } from '@/crypto';

const importKey = async function (bytes: Uint8Array, name: string, usages: KeyUsage[]): Promise<CryptoKey> {
  const crypto = await getCrypto();
  return await crypto.subtle.importKey('raw', bytes, { name }, true, usages);
};

const mergeUint8Array = function (arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }

  return result;
};

const splitByLengths = function (array: Uint8Array, lengths: number[]): Uint8Array[] {
  if (lengths.length === 0) {
    return [array];
  }

  const result = [];
  let offset = 0;

  for (const len of lengths) {
    if (offset + len > array.length) {
      result.push(array.slice(offset));
      offset = array.length;
      break;
    }
    result.push(array.slice(offset, offset + len));
    offset += len;
  }

  if (offset < array.length) {
    result.push(array.slice(offset));
  }

  return result;
};

export { importKey, mergeUint8Array, splitByLengths };
