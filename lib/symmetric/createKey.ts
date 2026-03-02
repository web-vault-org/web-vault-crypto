import { getCrypto } from '@/crypto';

/**
 * generates a random key with desired size.
 * @param sizeInBytes - desired key size in bytes
 * @returns Promise with desired key as Uint8Array
 */
const createKey = async function ({ sizeInBytes }: { sizeInBytes: number }): Promise<Uint8Array> {
  if (sizeInBytes < 8) {
    throw new Error('Invalid length. Must be at least 8');
  }

  const crypto = getCrypto();
  const key = new Uint8Array(sizeInBytes);
  crypto.getRandomValues(key);
  return key;
};

export { createKey };
