import { getCrypto } from '@/crypto';

const importKey = async function (bytes: Uint8Array, name: string, usages: KeyUsage[], extractable: boolean): Promise<CryptoKey> {
  const crypto = getCrypto();
  return await crypto.subtle.importKey('raw', bytes, { name }, extractable, usages);
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

const createDataString = function (data: Record<string, unknown>, exclude?: string[]): string {
  const filteredData = { ...data };
  for (const ex of exclude ?? []) {
    delete filteredData[ex];
  }
  return JSON.stringify(filteredData);
};

export { importKey, splitByLengths, createDataString };
