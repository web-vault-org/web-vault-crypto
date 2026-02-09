import crypto from 'crypto';
import { wrapKey, unwrapKey } from '@/wrapping';

// Helper für zufällige Bytes
function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

describe('wrapping', () => {
  let kek: Uint8Array;
  let keys: Uint8Array[];

  beforeEach(() => {
    // Key Encryption Key (KEK) 256 Bit
    kek = randomBytes(32);

    // Beispiel Keys zum Wrappen
    keys = [randomBytes(16), randomBytes(16)]; // zwei Keys à 16 Bytes
  });

  test('wrapKey gibt Uint8Array zurück', async () => {
    const wrapped = await wrapKey({ keys, kek });
    expect(wrapped).toBeInstanceOf(Uint8Array);
    expect(wrapped.length).toBeGreaterThan(0);
  });

  test('wrapKey mit Base64-Encoding', async () => {
    const wrappedBase64 = await wrapKey({ keys, kek, encode: true });
    expect(typeof wrappedBase64).toBe('string');
    // Optional: Prüfen, ob Base64-String gültig ist
    expect(wrappedBase64).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  test('unwrapKey liefert die originalen Keys zurück', async () => {
    const wrapped = await wrapKey({ keys, kek });
    const unwrapped = await unwrapKey({ wrappedKeys: wrapped, kek, length: keys.map((k) => k.length) });

    expect(unwrapped.length).toBe(keys.length);
    unwrapped.forEach((u, i) => {
      expect(u).toEqual(keys[i]);
    });
  });

  test('unwrapKey ohne length splitten gibt ein Array mit gesamtem Key zurück', async () => {
    const wrapped = await wrapKey({ keys, kek });
    const unwrapped = await unwrapKey({ wrappedKeys: wrapped, kek });

    // Da keine length übergeben, sollte ein einzelnes Array zurückkommen
    expect(unwrapped.length).toBe(1);
    const mergedOriginal = keys.reduce((acc, k) => {
      const tmp = new Uint8Array(acc.length + k.length);
      tmp.set(acc, 0);
      tmp.set(k, acc.length);
      return tmp;
    }, new Uint8Array());
    expect(unwrapped[0]).toEqual(mergedOriginal);
  });

  test('unwrapKey mit unvollständigen length-Array behandelt Rest korrekt', async () => {
    const wrapped = await wrapKey({ keys, kek });
    const partialLength = [16]; // nur erste 16 Bytes splitten
    const unwrapped = await unwrapKey({ wrappedKeys: wrapped, kek, length: partialLength });

    expect(unwrapped.length).toBe(2); // erste 16, rest
    expect(unwrapped[0]).toEqual(keys[0]);
    expect(unwrapped[1]).toEqual(keys[1]);
  });

  test('wrap + unwrap ist symmetrisch', async () => {
    const wrapped = await wrapKey({ keys, kek });
    const unwrapped = await unwrapKey({ wrappedKeys: wrapped, kek, length: keys.map((k) => k.length) });

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
});
