import { arrayBufferToPem, pemToArrayBuffer, validatePrivateEncryptionKey, validatePrivateSigningKey } from '@/asymmetric/util';
import { encrypt, decrypt } from '@/symmetric';

/**
 * wraps/encrypts private key for sign and verify
 * @param privateSigningKey - private key (PEM, Ed25519)
 * @param key - key used to encrypt the private key (length (in bytes) must be 16, 24 or 32 bytes)
 * @param encode - boolean, if wrapped key should be base64-encoded
 * @returns Promise with wrappedKey, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const wrapPrivateSigningKey = async function ({
  privateSigningKey,
  key,
  encode
}: {
  privateSigningKey: string;
  key: Uint8Array;
  encode?: boolean;
}): Promise<string> {
  validatePrivateSigningKey(privateSigningKey);
  const dataArrayBuffer = pemToArrayBuffer(privateSigningKey);
  const content = new Uint8Array(dataArrayBuffer);
  return (await encrypt({ content, key, encode: encode ?? false, additionalData: ['privateSigningKey'] })) as string;
};

/**
 * unwraps/decrypts private key for sign and verify
 * @param wrappedPrivateSigningKey - key to unwrap/decrypt (Uint8Array or base64-encoded string)
 * @param key - key used to encrypt the key (length (in bytes) must be 16, 24 or 32 bytes)
 * @returns Promise with unwrapped key (string)
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

/**
 * wraps/encrypts private key for encryption and decryption
 * @param privateEncryptionKey - private key (PEM, RSA-OAEP)
 * @param key - key used to encrypt the private key (length (in bytes) must be 16, 24 or 32 bytes)
 * @param encode - boolean, if wrapped key should be base64-encoded
 * @returns Promise with wrappedKey, as base64-encoded string if `encode` is true, as Uint8Array if not
 */
const wrapPrivateEncryptionKey = async function ({
  privateEncryptionKey,
  key,
  encode
}: {
  privateEncryptionKey: string;
  key: Uint8Array;
  encode?: boolean;
}): Promise<string | Uint8Array> {
  validatePrivateEncryptionKey(privateEncryptionKey);
  const dataArrayBuffer = pemToArrayBuffer(privateEncryptionKey);
  const content = new Uint8Array(dataArrayBuffer);
  return await encrypt({ content, key, encode: encode ?? false, additionalData: ['privateEncryptionKey'] });
};

/**
 * unwraps/decrypts private key for encryption and decryption
 * @param wrappedPrivateEncryptionKey - key to unwrap/decrypt (Uint8Array or base64-encoded string)
 * @param key - key used to encrypt the key (length (in bytes) must be 16, 24 or 32 bytes)
 * @returns Promise with unwrapped key (string)
 */
const unwrapPrivateEncryptionKey = async function ({
  wrappedPrivateEncryptionKey,
  key
}: {
  wrappedPrivateEncryptionKey: string | Uint8Array;
  key: Uint8Array;
}): Promise<string> {
  const content = (await decrypt({ content: wrappedPrivateEncryptionKey, key, additionalData: ['privateEncryptionKey'] })) as Uint8Array;
  const dataArrayBuffer = content.buffer;
  return arrayBufferToPem(dataArrayBuffer, 'PRIVATE KEY');
};

export { wrapPrivateSigningKey, unwrapPrivateSigningKey, wrapPrivateEncryptionKey, unwrapPrivateEncryptionKey };
