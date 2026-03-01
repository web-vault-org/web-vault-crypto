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

export { arrayBufferToPem, pemToArrayBuffer, importEd25519PrivateKeyFromPEM, importEd25519PublicKeyFromPEM };
