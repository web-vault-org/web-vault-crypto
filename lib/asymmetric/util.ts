import { getCrypto } from '@/crypto';

const arrayBufferToPem = function (buffer: ArrayBuffer, label: string): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const formatted = base64.match(/.{1,64}/g)?.join('\n');
  return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
};

const pemToArrayBuffer = function (pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
};

const importEd25519PublicKeyFromPEM = async function (pem: string): Promise<CryptoKey> {
  const crypto = getCrypto();
  const buffer = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('spki', buffer, { name: 'Ed25519' }, true, ['verify']);
};

const importEd25519PrivateKeyFromPEM = async function (pem: string): Promise<CryptoKey> {
  const crypto = getCrypto();
  const buffer = pemToArrayBuffer(pem);
  return crypto.subtle.importKey('pkcs8', buffer, { name: 'Ed25519' }, true, ['sign']);
};

const validatePrivateSigningKey = function (key: string): void {
  const regex = /^-----BEGIN PRIVATE KEY-----\n[a-z0-9+/]{64}\n-----END PRIVATE KEY-----$/isu;
  if (!regex.test(key)) {
    throw new Error('Invalid key format. Must be private Ed25519 key in PEM format');
  }
};

const validatePublicSigningKey = function (key: string): void {
  const regex = /^-----BEGIN PUBLIC KEY-----\n[a-z0-9+/]{59}=\n-----END PUBLIC KEY-----$/isu;
  if (!regex.test(key)) {
    throw new Error('Invalid key format. Must be public Ed25519 key in PEM format');
  }
};

const validatePrivateEncryptionKey = function (key: string): void {
  const regex = /^-----BEGIN PRIVATE KEY-----\n([a-z0-9+/]{64}\n){25}[a-z0-9+/]{20,30}={0,2}\n-----END PRIVATE KEY-----$/isu;
  if (!regex.test(key)) {
    throw new Error('Invalid key format. Must be private RSA-OAEP key in PEM format');
  }
};

const validatePublicEncryptionKey = function (key: string): void {
  const regex = /^-----BEGIN PUBLIC KEY-----\n([a-z0-9+/]{64}\n){6}[a-z0-9+/]{5,15}={0,2}\n-----END PUBLIC KEY-----$/isu;
  if (!regex.test(key)) {
    throw new Error('Invalid key format. Must be public RSA-OAEP key in PEM format');
  }
};

const rsaOaepParams = { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };

export {
  arrayBufferToPem,
  pemToArrayBuffer,
  importEd25519PrivateKeyFromPEM,
  importEd25519PublicKeyFromPEM,
  validatePrivateSigningKey,
  validatePublicSigningKey,
  validatePrivateEncryptionKey,
  validatePublicEncryptionKey,
  rsaOaepParams
};
