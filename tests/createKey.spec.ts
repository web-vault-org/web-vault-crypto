import { createKey } from '@/createKey';

describe('createKey', () => {
  it('creates 32 byte key.', async () => {
    const key = await createKey({ sizeInBytes: 32 });

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('creates random keys.', async () => {
    const key1 = await createKey({ sizeInBytes: 32 });
    const key2 = await createKey({ sizeInBytes: 32 });

    expect(key1).not.toEqual(key2);
  });

  it('rejects if key length is less then 8.', async () => {
    let error: Error | null = null;

    try {
      await createKey({ sizeInBytes: 7 });
    } catch (err: unknown) {
      error = err as Error;
    }

    expect(error).not.toBeNull();
    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toEqual('Invalid length. Must be at least 8');
  });

  describe('constraints', () => {
    it('rejects if key length is less then 8 - test.', async () => {
      await expect(createKey({ sizeInBytes: 7 })).rejects.toThrow('Invalid length. Must be at least 8');
    });
  });
});
