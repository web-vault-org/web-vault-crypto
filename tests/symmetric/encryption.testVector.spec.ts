import crypto from 'crypto';
import { encrypt } from '@/symmetric/encryption';

describe('encrypt – official test vector', () => {
  const masterKey = Uint8Array.from([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  ]);

  const contentKeyBytes = Uint8Array.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  ]);

  const iv = Uint8Array.from([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]);

  const plaintext = Uint8Array.from([0x41, 0x42, 0x43, 0x44]); // ABCD

  let originalGetRandomValues: typeof crypto.webcrypto.getRandomValues;
  let originalGenerateKey: typeof crypto.webcrypto.subtle.generateKey;

  beforeAll(() => {
    // mock IV
    originalGetRandomValues = crypto.webcrypto.getRandomValues;
    crypto.webcrypto.getRandomValues = jest.fn().mockImplementation((arr: Uint8Array) => {
      arr.set(iv);
      return arr;
    });

    // mock content key generation
    originalGenerateKey = crypto.webcrypto.subtle.generateKey;
    crypto.webcrypto.subtle.generateKey = jest
      .fn()
      .mockResolvedValue(crypto.webcrypto.subtle.importKey('raw', contentKeyBytes, { name: 'AES-GCM' }, true, ['encrypt']));
  });

  afterAll(() => {
    crypto.webcrypto.getRandomValues = originalGetRandomValues;
    crypto.webcrypto.subtle.generateKey = originalGenerateKey;
  });

  test('matches reference ciphertext', async () => {
    const encrypted = await encrypt({
      content: plaintext,
      key: masterKey
    });

    expect(encrypted).toBeInstanceOf(Uint8Array);

    const result = encrypted as Uint8Array;

    expect(result.length).toBeGreaterThan(52);
    expect(result.slice(40, 52)).toEqual(iv);
    expect(Array.from(result)).toMatchSnapshot();
  });
});
