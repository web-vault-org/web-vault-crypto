import crypto from 'crypto';
import { createEncryptionKeyPair, createSigningKeyPair } from '@/asymmetric/createKeyPair';
import { pemToArrayBuffer, rsaOaepParams } from '../../lib/asymmetric/util';

describe('createKey', () => {
  describe('createSigningKeyPair', () => {
    it('should generate a valid Ed25519 key pair in PEM format.', async () => {
      const result = await createSigningKeyPair();

      expect(result).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(result.publicKey).toContain('-----END PUBLIC KEY-----');
      expect(result.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(result.privateKey).toContain('-----END PRIVATE KEY-----');
      expect(result.publicKey.length).toBeGreaterThan(100);
      expect(result.privateKey.length).toBeGreaterThan(100);
      expect(result.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----\n[a-z0-9+/]{59}=\n-----END PUBLIC KEY-----$/isu);
      expect(result.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----\n[a-z0-9+/]{64}\n-----END PRIVATE KEY-----$/isu);
    });

    it('should produce different keys on multiple invocations.', async () => {
      const keyPair1 = await createSigningKeyPair();
      const keyPair2 = await createSigningKeyPair();

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });

    it('should generate keys that can sign and verify data.', async () => {
      const { publicKey, privateKey } = await createSigningKeyPair();

      const pemToArrayBuffer = (pem: string): ArrayBuffer => {
        const base64 = pem
          .replace(/-----BEGIN [^-]+-----/, '')
          .replace(/-----END [^-]+-----/, '')
          .replace(/\s/g, '');

        const binary = Buffer.from(base64, 'base64');
        return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength);
      };
      const publicKeyImported = await crypto.webcrypto.subtle.importKey('spki', pemToArrayBuffer(publicKey), { name: 'Ed25519' }, true, ['verify']);
      const privateKeyImported = await crypto.webcrypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKey), { name: 'Ed25519' }, true, ['sign']);
      const data = new TextEncoder().encode('test message');
      const signature = await crypto.webcrypto.subtle.sign('Ed25519', privateKeyImported, data);
      const isValid = await crypto.webcrypto.subtle.verify('Ed25519', publicKeyImported, signature, data);

      expect(isValid).toBe(true);
    });
  });

  describe('createEncryptionKeyPair', () => {
    it('should generate a valid RSA-OAEP key pair in PEM format.', async () => {
      const result = await createEncryptionKeyPair();

      expect(result).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(result.privateKey).toContain('-----END PRIVATE KEY-----');
      expect(result.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(result.publicKey).toContain('-----END PUBLIC KEY-----');
      expect(result.publicKey.length).toBeGreaterThan(300);
      expect(result.privateKey.length).toBeGreaterThan(300);
      expect(result.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----\n([a-z0-9+/]{64}\n){6}[a-z0-9+/]{5,15}={0,2}\n-----END PUBLIC KEY-----$/isu);
      expect(result.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----\n([a-z0-9+/]{64}\n){25}[a-z0-9+/]{20,30}={0,2}\n-----END PRIVATE KEY-----$/isu);
    });

    it('should produce different keys on multiple invocations.', async () => {
      const keyPair1 = await createEncryptionKeyPair();
      const keyPair2 = await createEncryptionKeyPair();

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });

    it('should generate keys that can wrap and unwrap symmetric key.', async () => {
      const keyPairPem = await createEncryptionKeyPair();
      const publicKeyPem = keyPairPem.publicKey;
      const privateKeyPem = keyPairPem.privateKey;
      const symmetricKey = crypto.webcrypto.getRandomValues(new Uint8Array(32));
      const publicKeyImported = await crypto.webcrypto.subtle.importKey('spki', pemToArrayBuffer(publicKeyPem), rsaOaepParams, true, ['wrapKey']);
      const privateKeyImported = await crypto.webcrypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKeyPem), rsaOaepParams, true, [
        'unwrapKey'
      ]);
      const symmetricKeyImported = await crypto.webcrypto.subtle.importKey('raw', symmetricKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);

      const wrappedKey = await crypto.webcrypto.subtle.wrapKey('raw', symmetricKeyImported, publicKeyImported, { name: 'RSA-OAEP' });
      const unwrappedKey = await crypto.webcrypto.subtle.unwrapKey(
        'raw',
        wrappedKey,
        privateKeyImported,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
      );
      const unwrappedKeyExported = await crypto.webcrypto.subtle.exportKey('raw', unwrappedKey);

      expect(new Uint8Array(unwrappedKeyExported)).toEqual(symmetricKey);
    });
  });
});
