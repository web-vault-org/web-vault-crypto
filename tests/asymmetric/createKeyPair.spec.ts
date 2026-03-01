import crypto from 'crypto';
import { createSigningKeyPair } from '@/asymmetric/createKeyPair';

describe('createSigningKeyPair (integration)', () => {
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
