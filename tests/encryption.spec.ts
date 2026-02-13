import crypto from 'crypto';
import { encrypt, decrypt } from '@/encryption';

const randomBytes = function (length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.webcrypto.getRandomValues(bytes);
  return bytes;
};

describe('encryption', () => {
  let masterKey: Uint8Array;

  beforeEach(() => {
    masterKey = randomBytes(32);
  });

  test('encrypt + decrypt Uint8Array', async () => {
    const plaintext = randomBytes(128);

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey
    });

    expect(encrypted).toBeInstanceOf(Uint8Array);

    const decrypted = await decrypt({
      content: encrypted as Uint8Array,
      key: masterKey
    });

    expect(decrypted).toBeInstanceOf(Uint8Array);
    expect(decrypted).toEqual(plaintext);
  });

  test('encrypt + decrypt string', async () => {
    const plaintext = 'Hello secure world';

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey
    });

    const decrypted = await decrypt({
      content: encrypted as Uint8Array,
      key: masterKey,
      asString: true
    });

    expect(decrypted).toBe(plaintext);
  });

  test('encrypt returns base64 string when encode=true', async () => {
    const plaintext = 'base64 test';

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey,
      encode: true
    });

    expect(typeof encrypted).toBe('string');
    expect(encrypted).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  test('decrypt accepts base64 input', async () => {
    const plaintext = 'base64 decrypt test';

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey,
      encode: true
    });

    const decrypted = await decrypt({
      content: encrypted as string,
      key: masterKey,
      asString: true
    });

    expect(decrypted).toBe(plaintext);
  });

  test('encrypt + decrypt with additionalData', async () => {
    const plaintext = 'authenticated data';
    const additionalData = ['file.txt', '2026-02-10', 'user-123'];

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey,
      additionalData
    });

    const decrypted = await decrypt({
      content: encrypted as Uint8Array,
      key: masterKey,
      additionalData,
      asString: true
    });

    expect(decrypted).toBe(plaintext);
  });

  test('decrypt fails if additionalData is different', async () => {
    const plaintext = 'tamper proof';
    const additionalData = ['id-1'];

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey,
      additionalData
    });

    await expect(
      decrypt({
        content: encrypted as Uint8Array,
        key: masterKey,
        additionalData: ['id-2'], // different AAD
        asString: true
      })
    ).rejects.toThrow();
  });

  test('decrypt fails with wrong key', async () => {
    const plaintext = 'wrong key test';
    const wrongKey = randomBytes(32);

    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey
    });

    await expect(
      decrypt({
        content: encrypted as Uint8Array,
        key: wrongKey,
        asString: true
      })
    ).rejects.toThrow();
  });

  test('ciphertext differs for same plaintext (random IV)', async () => {
    const plaintext = 'same input';

    const a = await encrypt({ content: plaintext, key: masterKey });
    const b = await encrypt({ content: plaintext, key: masterKey });

    expect(a).not.toEqual(b);
  });

  describe('constraints', () => {
    it('encryption rejects if key length is not 16, 24 or 32.', async () => {
      await expect(encrypt({ content: '', key: new Uint8Array(15) })).rejects.toThrow('Invalid key length. Must be 16, 24 or 32');
    });

    it('decryption rejects if key length is not 16, 24 or 32.', async () => {
      await expect(decrypt({ content: '', key: new Uint8Array(15) })).rejects.toThrow('Invalid key length. Must be 16, 24 or 32');
    });
  });
});
