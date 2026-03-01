import crypto from 'crypto';
import { wrapPrivateSigningKey, unwrapPrivateSigningKey, wrapPrivateEncryptionKey, unwrapPrivateEncryptionKey } from '@/asymmetric/wrapping';
import { createEncryptionKeyPair, createSigningKeyPair } from '@/asymmetric/createKeyPair';

describe('wrapping', () => {
  describe('wrapPrivateSigningKey / unwrapPrivateSigningKey', () => {
    let privateKeyPem: string;
    let symmetricKey: Uint8Array;

    beforeAll(async () => {
      const keyPair = await createSigningKeyPair();
      privateKeyPem = keyPair.privateKey;
      symmetricKey = crypto.webcrypto.getRandomValues(new Uint8Array(32));
    });

    it('should wrap and unwrap the private key correctly, base64 string.', async () => {
      const wrappedKey = await wrapPrivateSigningKey({
        privateSigningKey: privateKeyPem,
        key: symmetricKey,
        encode: true
      });

      const unwrappedKey = await unwrapPrivateSigningKey({
        wrappedPrivateSigningKey: wrappedKey,
        key: symmetricKey
      });

      expect(typeof wrappedKey).toBe('string');
      expect(wrappedKey.length).toBeGreaterThan(20);
      expect(unwrappedKey).toBe(privateKeyPem);
    });

    it('should wrap and unwrap the private key correctly, Uint8Array.', async () => {
      const wrappedKey = await wrapPrivateSigningKey({
        privateSigningKey: privateKeyPem,
        key: symmetricKey
      });

      const unwrappedKey = await unwrapPrivateSigningKey({
        wrappedPrivateSigningKey: wrappedKey,
        key: symmetricKey
      });

      expect(wrappedKey).toBeInstanceOf(Uint8Array);
      expect(wrappedKey.length).toBeGreaterThan(20);
      expect(unwrappedKey).toBe(privateKeyPem);
    });

    it('should fail to unwrap with a wrong key.', async () => {
      const wrappedKey = await wrapPrivateSigningKey({
        privateSigningKey: privateKeyPem,
        key: symmetricKey,
        encode: true
      });

      const wrongKey = crypto.getRandomValues(new Uint8Array(32));

      await expect(
        unwrapPrivateSigningKey({
          wrappedPrivateSigningKey: wrappedKey,
          key: wrongKey
        })
      ).rejects.toThrow();
    });

    it('should produce different ciphertexts on multiple wraps.', async () => {
      const wrappedKey1 = await wrapPrivateSigningKey({ privateSigningKey: privateKeyPem, key: symmetricKey, encode: true });
      const wrappedKey2 = await wrapPrivateSigningKey({ privateSigningKey: privateKeyPem, key: symmetricKey, encode: true });

      expect(wrappedKey1).not.toBe(wrappedKey2);
    });

    it('should correctly unwrap multiple times.', async () => {
      const wrappedKey = await wrapPrivateSigningKey({ privateSigningKey: privateKeyPem, key: symmetricKey });

      const unwrapped1 = await unwrapPrivateSigningKey({ wrappedPrivateSigningKey: wrappedKey, key: symmetricKey });
      const unwrapped2 = await unwrapPrivateSigningKey({ wrappedPrivateSigningKey: wrappedKey, key: symmetricKey });

      expect(unwrapped1).toBe(privateKeyPem);
      expect(unwrapped2).toBe(privateKeyPem);
    });

    describe('constraints', () => {
      it('wrapSigningKey fails with invalid privateKey, not pem.', async () => {
        await expect(wrapPrivateSigningKey({ privateSigningKey: 'invalid', key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private Ed25519 key in PEM format'
        );
      });

      it('wrapSigningKey fails with invalid privateKey, public instead of private.', async () => {
        const newKeyPair = await createSigningKeyPair();
        const publicKeyPem = newKeyPair.publicKey;

        await expect(wrapPrivateSigningKey({ privateSigningKey: publicKeyPem, key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private Ed25519 key in PEM format'
        );
      });

      it('wrapSigningKey fails with invalid privateKey, encryption instead of signing.', async () => {
        const newKeyPair = await createEncryptionKeyPair();

        await expect(wrapPrivateSigningKey({ privateSigningKey: newKeyPair.privateKey, key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private Ed25519 key in PEM format'
        );
      });
    });
  });

  describe('wrapPrivateEncryptionKey / unwrapPrivateEncryptionKey', () => {
    let privateKeyPem: string;
    let symmetricKey: Uint8Array;

    beforeAll(async () => {
      const keyPair = await createEncryptionKeyPair();
      privateKeyPem = keyPair.privateKey;
      symmetricKey = crypto.webcrypto.getRandomValues(new Uint8Array(32));
    });

    it('should wrap and unwrap the private key correctly, base64 string.', async () => {
      const wrappedKey = await wrapPrivateEncryptionKey({
        privateEncryptionKey: privateKeyPem,
        key: symmetricKey,
        encode: true
      });

      const unwrappedKey = await unwrapPrivateEncryptionKey({
        wrappedPrivateEncryptionKey: wrappedKey,
        key: symmetricKey
      });

      expect(typeof wrappedKey).toBe('string');
      expect(wrappedKey.length).toBeGreaterThan(20);
      expect(unwrappedKey).toBe(privateKeyPem);
    });

    it('should wrap and unwrap the private key correctly, Uint8Array.', async () => {
      const wrappedKey = await wrapPrivateEncryptionKey({
        privateEncryptionKey: privateKeyPem,
        key: symmetricKey
      });

      const unwrappedKey = await unwrapPrivateEncryptionKey({
        wrappedPrivateEncryptionKey: wrappedKey,
        key: symmetricKey
      });

      expect(wrappedKey).toBeInstanceOf(Uint8Array);
      expect(wrappedKey.length).toBeGreaterThan(20);
      expect(unwrappedKey).toBe(privateKeyPem);
    });

    it('should fail to unwrap with a wrong key.', async () => {
      const wrappedKey = await wrapPrivateEncryptionKey({
        privateEncryptionKey: privateKeyPem,
        key: symmetricKey,
        encode: true
      });

      const wrongKey = crypto.getRandomValues(new Uint8Array(32));

      await expect(
        unwrapPrivateEncryptionKey({
          wrappedPrivateEncryptionKey: wrappedKey,
          key: wrongKey
        })
      ).rejects.toThrow();
    });

    it('should produce different ciphertexts on multiple wraps.', async () => {
      const wrappedKey1 = await wrapPrivateEncryptionKey({ privateEncryptionKey: privateKeyPem, key: symmetricKey, encode: true });
      const wrappedKey2 = await wrapPrivateEncryptionKey({ privateEncryptionKey: privateKeyPem, key: symmetricKey, encode: true });

      expect(wrappedKey1).not.toBe(wrappedKey2);
    });

    it('should correctly unwrap multiple times.', async () => {
      const wrappedKey = await wrapPrivateEncryptionKey({ privateEncryptionKey: privateKeyPem, key: symmetricKey });

      const unwrapped1 = await unwrapPrivateEncryptionKey({ wrappedPrivateEncryptionKey: wrappedKey, key: symmetricKey });
      const unwrapped2 = await unwrapPrivateEncryptionKey({ wrappedPrivateEncryptionKey: wrappedKey, key: symmetricKey });

      expect(unwrapped1).toBe(privateKeyPem);
      expect(unwrapped2).toBe(privateKeyPem);
    });

    describe('constraints', () => {
      it('wrapEncryptionKey fails with invalid privateKey, not pem.', async () => {
        await expect(wrapPrivateEncryptionKey({ privateEncryptionKey: 'invalid', key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private RSA-OAEP key in PEM format'
        );
      });

      it('wrapEncryptionKey fails with invalid privateKey, public instead of private.', async () => {
        const newKeyPair = await createEncryptionKeyPair();
        const publicKeyPem = newKeyPair.publicKey;

        await expect(wrapPrivateEncryptionKey({ privateEncryptionKey: publicKeyPem, key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private RSA-OAEP key in PEM format'
        );
      });

      it('wrapEncryptionKey fails with invalid privateKey, signing instead of encryption.', async () => {
        const newKeyPair = await createSigningKeyPair();

        await expect(wrapPrivateEncryptionKey({ privateEncryptionKey: newKeyPair.privateKey, key: new Uint8Array() })).rejects.toThrow(
          'Invalid key format. Must be private RSA-OAEP key in PEM format'
        );
      });
    });
  });
});
