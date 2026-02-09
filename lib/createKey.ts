import { getCrypto } from '@/crypto';

const createKey = async function ({ sizeInBytes }: { sizeInBytes: number }): Promise<Uint8Array> {
  const crypto = await getCrypto();
  const key = new Uint8Array(sizeInBytes);
  crypto.getRandomValues(key);
  return key;
};

export { createKey };
