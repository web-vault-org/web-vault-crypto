import crypto from 'crypto';
import { wrapKeys, unwrapKeys } from '@/wrapping';

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

describe('wrapping', () => {
  let kek: Uint8Array;
  let keys: Uint8Array[];

  beforeEach(() => {
    kek = randomBytes(32);
    keys = [randomBytes(16), randomBytes(16)];
  });

  it('wrapKey returns Uint8Array', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    expect(wrapped).toBeInstanceOf(Uint8Array);
    expect(wrapped.length).toBeGreaterThan(0);
  });

  it('wrapKey with Base64-Encoding.', async () => {
    const wrappedBase64 = await wrapKeys({ keys, kek, encode: true });
    expect(typeof wrappedBase64).toBe('string');
    expect(wrappedBase64).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it('unwrapKey returns original keys.', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek, lengths: keys.map((k) => k.length) });

    expect(unwrapped.length).toBe(keys.length);
    unwrapped.forEach((u, i) => {
      expect(u).toEqual(keys[i]);
    });
  });

  it('unwrapKey without length returns one-value-array with full length.', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek });

    expect(unwrapped.length).toBe(1);
    const mergedOriginal = keys.reduce((acc, k) => {
      const tmp = new Uint8Array(acc.length + k.length);
      tmp.set(acc, 0);
      tmp.set(k, acc.length);
      return tmp;
    }, new Uint8Array());
    expect(unwrapped[0]).toEqual(mergedOriginal);
  });

  it('unwrapKey with partially filled length-Array handles remaining correctly', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const partialLength = [16];
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek, lengths: partialLength });

    expect(unwrapped.length).toBe(2);
    expect(unwrapped[0]).toEqual(keys[0]);
    expect(unwrapped[1]).toEqual(keys[1]);
  });

  it('wrap + unwrap is symmetric', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek, lengths: keys.map((k) => k.length) });

    const mergedUnwrapped = unwrapped.reduce((acc, k) => {
      const tmp = new Uint8Array(acc.length + k.length);
      tmp.set(acc, 0);
      tmp.set(k, acc.length);
      return tmp;
    }, new Uint8Array());

    const mergedOriginal = keys.reduce((acc, k) => {
      const tmp = new Uint8Array(acc.length + k.length);
      tmp.set(acc, 0);
      tmp.set(k, acc.length);
      return tmp;
    }, new Uint8Array());

    expect(mergedUnwrapped).toEqual(mergedOriginal);
  });

  describe('constraints', () => {
    it('wrapKeys rejects if keys length is not multiple of 8.', async () => {
      await expect(wrapKeys({ keys: [new Uint8Array(8), new Uint8Array(9)], kek: new Uint8Array(32) })).rejects.toThrow(
        'Invalid keys length. Must be multiple of 8 bytes'
      );
    });

    it('wrapKeys rejects if kek length is not 16, 24 or 32.', async () => {
      await expect(wrapKeys({ keys: [new Uint8Array(8), new Uint8Array(8)], kek: new Uint8Array(31) })).rejects.toThrow(
        'Invalid kek length. Must be 16, 24 or 32'
      );
    });

    it('unwrapKeys rejects if kek length is not 16, 24 or 32.', async () => {
      await expect(unwrapKeys({ wrappedKeys: new Uint8Array(), kek: new Uint8Array(31) })).rejects.toThrow(
        'Invalid kek length. Must be 16, 24 or 32'
      );
    });
  });
});
