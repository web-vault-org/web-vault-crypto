import { getCrypto } from '@/crypto';
import {
  importEd25519PrivateKeyFromPEM,
  importEd25519PublicKeyFromPEM,
  validatePrivateSigningKey,
  validatePublicSigningKey
} from '@/asymmetric/util';
import { encode, decode } from '@/base64';
import { createDataString } from '@/util';

const sign = async function ({
  privateSigningKey,
  data,
  exclude
}: {
  privateSigningKey: string;
  data: Record<string, unknown>;
  exclude?: string[];
}): Promise<string> {
  validatePrivateSigningKey(privateSigningKey);
  const crypto = getCrypto();
  const encoder = new TextEncoder();
  const dataString = createDataString(data, exclude);
  const privateKey = await importEd25519PrivateKeyFromPEM(privateSigningKey);
  const signature = await crypto.subtle.sign('Ed25519', privateKey, encoder.encode(dataString));
  return encode(new Uint8Array(signature));
};

const verify = async function ({
  publicSigningKey,
  data,
  signature,
  exclude
}: {
  publicSigningKey: string;
  data: Record<string, unknown>;
  signature: string;
  exclude?: string[];
}): Promise<boolean> {
  validatePublicSigningKey(publicSigningKey);
  const crypto = getCrypto();
  const encoder = new TextEncoder();
  const dataString = createDataString(data, exclude);
  const publicKey = await importEd25519PublicKeyFromPEM(publicSigningKey);
  return await crypto.subtle.verify('Ed25519', publicKey, decode(signature), encoder.encode(dataString));
};

export { sign, verify };
