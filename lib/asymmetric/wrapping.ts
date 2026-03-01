import { arrayBufferToPem, pemToArrayBuffer, validatePrivateSigningKey } from '@/asymmetric/util';
import { encrypt, decrypt } from '@/symmetric';

/**
 * wraps/encrypts private key for sign and verify
 * @param privateSigningKey - private key (PEM, Ed25519)
 * @param key - key used to encrypt the private key (length (in bytes) must be 16, 24 or 32 bytes)
 * @param encode - boolean, if wrapped key should be base64-encoded
 * @returns Promise with wrappedKey, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const wrapPrivateSigningKey = async function ({ privateSigningKey, key, encode }: { privateSigningKey: string; key: Uint8Array, encode?: boolean }): Promise<string> {
  validatePrivateSigningKey(privateSigningKey);
  const dataArrayBuffer = pemToArrayBuffer(privateSigningKey);
  const content = new Uint8Array(dataArrayBuffer);
  return (await encrypt({ content, key, encode: encode ?? false, additionalData: ['privateSigningKey'] })) as string;
};

/**
 * unwraps/decrypts private key for sign and verify
 * @param wrappedPrivateSigningKey - key to unwrap/decrypt (Uint8Array or base64-encoded string)
 * @param key - key used to encrypt the keys (length (in bytes) must be 16, 24 or 32 bytes)
 * @returns Promise with unwrapped key (Uint8Array)
 */
const unwrapPrivateSigningKey = async function ({
  wrappedPrivateSigningKey,
  key
}: {
  wrappedPrivateSigningKey: string | Uint8Array;
  key: Uint8Array;
}): Promise<string> {
  const content = (await decrypt({ content: wrappedPrivateSigningKey, key, additionalData: ['privateSigningKey'] })) as Uint8Array;
  const dataArrayBuffer = content.buffer;
  return arrayBufferToPem(dataArrayBuffer, 'PRIVATE KEY');
};

export { wrapPrivateSigningKey, unwrapPrivateSigningKey };
