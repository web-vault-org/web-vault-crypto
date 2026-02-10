import { sign, verify } from '@/signing';

describe('signing', () => {
  const key1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const key2 = new Uint8Array([10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

  const data = {
    foo: 'bar',
    baz: 42,
    nested: { a: 1 }
  };

  test('sign returns a base64 string.', async () => {
    const signature = await sign({ data, key: key1 });

    expect(typeof signature).toBe('string');
    expect(signature).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  test('verify returns true for correct signature.', async () => {
    const signature = await sign({ data, key: key1 });
    const result = await verify({ data, key: key1, signature });

    expect(result).toBe(true);
  });

  test('verify returns false for wrong key.', async () => {
    const signature = await sign({ data, key: key1 });
    const result = await verify({ data, key: key2, signature });

    expect(result).toBe(false);
  });

  test('verify returns false for modified data.', async () => {
    const signature = await sign({ data, key: key1 });
    const modifiedData = { ...data, foo: 'baz' };
    const result = await verify({ data: modifiedData, key: key1, signature });

    expect(result).toBe(false);
  });

  test('exclude fields are ignored in signature - sign.', async () => {
    const signatureFull = await sign({ data, key: key1 });
    const signatureExcluded = await sign({ data, key: key1, exclude: ['baz'] });

    expect(signatureFull).not.toBe(signatureExcluded);
  });

  test('exclude fields are ignored in signature - verify.', async () => {
    const signatureExcluded = await sign({ data, key: key1, exclude: ['baz'] });

    const result = await verify({ data, key: key1, signature: signatureExcluded, exclude: ['baz'] });

    expect(result).toBe(true);
  });

  test('sign is deterministic for same input and key.', async () => {
    const sig1 = await sign({ data, key: key1 });
    const sig2 = await sign({ data, key: key1 });

    expect(sig1).toBe(sig2);
  });

  test('different keys produce different signatures.', async () => {
    const sig1 = await sign({ data, key: key1 });
    const sig2 = await sign({ data, key: key2 });

    expect(sig1).not.toBe(sig2);
  });
});
