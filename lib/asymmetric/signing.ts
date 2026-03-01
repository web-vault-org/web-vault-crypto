import { getCrypto } from '@/crypto';
import {
  importEd25519PrivateKeyFromPEM,
  importEd25519PublicKeyFromPEM,
  validatePrivateSigningKey,
  validatePublicSigningKey
} from '@/asymmetric/util';
import { encode, decode } from '@/base64';
import { createDataString } from '@/util';

/**
 * signs an object
 * @param data - object to sign
 * @param privateSigningKey - private key (PEM, Ed25519)
 * @param exclude - array with names of properties to exclude
 * @returns Promise with signature as base64-encoded string
 */
const sign = async function ({
  data,
  privateSigningKey,
  exclude
}: {
  data: Record<string, unknown>;
  privateSigningKey: string;
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

/**
 * verifies an object
 * @param data - object to verify
 * @param publicSigningKey - public key (PEM, Ed25519)
 * @param signature - signature as string to verify the object against
 * @param exclude - array with names of properties to exclude
 * @returns Promise with boolean, stating if object is authentic and integer
 */
const verify = async function ({
  data,
  publicSigningKey,
  signature,
  exclude
}: {
  data: Record<string, unknown>;
  publicSigningKey: string;
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
