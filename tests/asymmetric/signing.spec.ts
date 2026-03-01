import { sign, verify } from '@/asymmetric/signing';
import { createSigningKeyPair } from '@/asymmetric/createKeyPair';

describe('signing', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeAll(async () => {
    const keyPair = await createSigningKeyPair();
    privateKeyPem = keyPair.privateKey;
    publicKeyPem = keyPair.publicKey;
  });

  it('should sign and verify valid data.', async () => {
    const data = {
      id: 123,
      name: 'Johanna',
      active: true
    };

    const signature = await sign({
      privateSigningKey: privateKeyPem,
      data
    });
    const isValid = await verify({
      publicSigningKey: publicKeyPem,
      data,
      signature
    });

    expect(typeof signature).toBe('string');
    expect(signature.length).toBeGreaterThan(10);
    expect(isValid).toBe(true);
  });

  it('should fail verification if data is modified.', async () => {
    const originalData = {
      id: 1,
      role: 'admin'
    };
    const signature = await sign({
      privateSigningKey: privateKeyPem,
      data: originalData
    });
    const manipulatedData = {
      id: 1,
      role: 'user' // changed
    };

    const isValid = await verify({
      publicSigningKey: publicKeyPem,
      data: manipulatedData,
      signature
    });

    expect(isValid).toBe(false);
  });

  it('should fail verification with wrong public key.', async () => {
    const otherKeyPair = await createSigningKeyPair();
    const data = { foo: 'bar' };
    const signature = await sign({
      privateSigningKey: privateKeyPem,
      data
    });

    const isValid = await verify({
      publicSigningKey: otherKeyPair.publicKey,
      data,
      signature
    });

    expect(isValid).toBe(false);
  });

  it('should respect exclude fields.', async () => {
    const data = {
      id: 42,
      timestamp: 123456,
      value: 'secure'
    };
    const signature = await sign({
      privateSigningKey: privateKeyPem,
      data,
      exclude: ['timestamp']
    });
    const modifiedData = {
      ...data,
      timestamp: 999999
    };

    const isValid = await verify({
      publicSigningKey: publicKeyPem,
      data: modifiedData,
      signature,
      exclude: ['timestamp']
    });

    expect(isValid).toBe(true);
  });

  it('should fail if signature is tampered.', async () => {
    const data = { secure: true };
    const signature = await sign({
      privateSigningKey: privateKeyPem,
      data
    });
    const tamperedSignature = signature.substring(0, signature.length - 2) + 'ab';

    const isValid = await verify({
      publicSigningKey: publicKeyPem,
      data,
      signature: tamperedSignature
    });

    expect(isValid).toBe(false);
  });
});
