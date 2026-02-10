import { getCrypto } from '@/crypto';

const createDataString = function (data: Record<string, unknown>, exclude?: string[]): string {
  const filteredData = { ...data };
  for (const ex of exclude ?? []) {
    delete filteredData[ex];
  }
  return JSON.stringify(filteredData);
};

const hmac = async function (dataString: string, key: Uint8Array): Promise<string> {
  const crypto = await getCrypto();
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = encoder.encode(dataString);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  const hmacBytes = new Uint8Array(signature);
  return btoa(String.fromCharCode(...hmacBytes));
};

const sign = async function ({ data, key, exclude }: { data: Record<string, unknown>; key: Uint8Array; exclude?: string[] }): Promise<string> {
  const dataString = createDataString(data, exclude);
  return hmac(dataString, key);
};

const verify = async function ({
  data,
  key,
  signature,
  exclude
}: {
  data: Record<string, unknown>;
  key: Uint8Array;
  signature: string;
  exclude?: string[];
}): Promise<boolean> {
  const actualSignature = await sign({ data, key, exclude });
  return actualSignature === signature;
};

export { sign, verify };
