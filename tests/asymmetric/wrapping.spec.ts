import crypto from 'crypto';
import { wrapPrivateSigningKey, unwrapPrivateSigningKey } from '@/asymmetric/wrapping';
import { createSigningKeyPair } from '@/asymmetric/createKeyPair';

describe('wrapPrivateSigningKey / unwrapPrivateSigningKey', () => {
  let privateKeyPem: string;
  let symmetricKey: Uint8Array;

  beforeAll(async () => {
    const keyPair = await createSigningKeyPair();
    privateKeyPem = keyPair.privateKey;
    symmetricKey = crypto.webcrypto.getRandomValues(new Uint8Array(32));
  });

  it('should wrap and unwrap the private key correctly.', async () => {
    const wrappedKey = await wrapPrivateSigningKey({
      privateSigningKey: privateKeyPem,
      key: symmetricKey
    });

    const unwrappedKey = await unwrapPrivateSigningKey({
      wrappedPrivateSigningKey: wrappedKey,
      key: symmetricKey
    });

    expect(typeof wrappedKey).toBe('string');
    expect(wrappedKey.length).toBeGreaterThan(20);
    expect(unwrappedKey).toBe(privateKeyPem);
  });

  it('should fail to unwrap with a wrong key.', async () => {
    const wrappedKey = await wrapPrivateSigningKey({
      privateSigningKey: privateKeyPem,
      key: symmetricKey
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
    const wrappedKey1 = await wrapPrivateSigningKey({ privateSigningKey: privateKeyPem, key: symmetricKey });
    const wrappedKey2 = await wrapPrivateSigningKey({ privateSigningKey: privateKeyPem, key: symmetricKey });

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
  });
});
