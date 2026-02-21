import crypto from 'crypto';
import { wrapKeys, unwrapKeys, wrapKey, unwrapKey } from '@/wrapping';

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

  it('wrapKeys returns Uint8Array', async () => {
    const wrapped = await wrapKeys({ keys, kek });

    expect(wrapped.length).toBe(2);
    expect(wrapped[0]).toBeInstanceOf(Uint8Array);
    expect(wrapped[0].length).toBe(24);
  });

  it('wrapKey returns Uint8Array', async () => {
    const wrapped = await wrapKey({ key: keys.at(0) as Uint8Array, kek });
    expect(wrapped).toBeInstanceOf(Uint8Array);
    expect(wrapped.length).toBe(24);
  });

  it('wrapKeys with Base64-Encoding.', async () => {
    const wrappedBase64 = await wrapKeys({ keys, kek, encode: true });

    expect(wrappedBase64.length).toBe(2);
    expect(typeof wrappedBase64[0]).toBe('string');
    expect(wrappedBase64[0]).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it('unwrapKeys returns original keys.', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek });

    expect(unwrapped.length).toBe(keys.length);
    unwrapped.forEach((u, i) => {
      expect(u).toEqual(keys[i]);
    });
  });

  it('unwrapKey returns original key.', async () => {
    const wrapped = await wrapKey({ key: keys.at(0) as Uint8Array, kek });
    const unwrapped = await unwrapKey({ wrappedKey: wrapped, kek });

    expect(unwrapped.length).toBe(keys.at(0)?.length);
    expect(unwrapped).toEqual(keys.at(0));
  });

  it('wrap + unwrap is symmetric', async () => {
    const wrapped = await wrapKeys({ keys, kek });
    const unwrapped = await unwrapKeys({ wrappedKeys: wrapped, kek });

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
    it('wrapKey rejects if keys length is not 16, 24 or 32.', async () => {
      await expect(wrapKey({ key: new Uint8Array(64), kek: new Uint8Array(32) })).rejects.toThrow('Invalid key length. Must be 16, 24 or 32');
    });

    it('wrapKey rejects if kek length is not 16, 24 or 32.', async () => {
      await expect(wrapKey({ key: new Uint8Array(16), kek: new Uint8Array(40) })).rejects.toThrow('Invalid kek length. Must be 16, 24 or 32');
    });

    it('unwrapKey rejects if kek length is not 16, 24 or 32.', async () => {
      await expect(unwrapKey({ wrappedKey: new Uint8Array(16), kek: new Uint8Array(40) })).rejects.toThrow(
        'Invalid kek length. Must be 16, 24 or 32'
      );
    });
  });
});
