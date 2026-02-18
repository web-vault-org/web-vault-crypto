import { derivePasswordKey, hashPassword } from '@/hashing';
import { encode } from '@/base64';

jest.mock('@/createKey', () => {
  return {
    async createKey({ sizeInBytes }: { sizeInBytes: number }) {
      return new Uint8Array(sizeInBytes);
    }
  };
});

describe('hashing', () => {
  const argon2idHash = new Uint8Array([24, 27, 61, 130, 166, 76, 158, 118, 62, 106, 57, 57, 176, 85, 85, 199, 154, 35, 41, 53, 29, 249, 240, 0]);
  const pbkdf2Hash = new Uint8Array([177, 57, 194, 63, 89, 103, 199, 10, 218, 30, 41, 67, 190, 9, 252, 161, 135, 109, 249, 67, 151, 133, 239, 226]);

  it('derivePasswordKey creates key from password, using new salt, no type specified.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24 });

    expect(salt).toEqual('AAAAAAAAAAAAAAAAAAAAAA==');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(argon2idHash);
  });

  it('derivePasswordKey creates key from password, using new salt, type=argon2id.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24, type: 'argon2id' });

    expect(salt).toEqual('AAAAAAAAAAAAAAAAAAAAAA==');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(argon2idHash);
  });

  it('derivePasswordKey creates key from password, using new salt, type=pbkdf2.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24, type: 'pbkdf2' });

    expect(salt).toEqual('AAAAAAAAAAAAAAAAAAAAAA==');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(pbkdf2Hash);
  });

  it('derivePasswordKey creates key from password, using given salt.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24, salt: 'givenSalt1234567' });

    expect(salt).toEqual('givenSalt1234567');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(
      new Uint8Array([102, 13, 10, 140, 130, 0, 112, 70, 113, 217, 97, 59, 247, 118, 18, 101, 129, 249, 65, 226, 148, 181, 56, 37])
    );
  });

  it('hashPassword creates hash from password, using new salt.', async () => {
    const [salt, hash] = await hashPassword({ password: 'p8ssw0rd!', sizeInBytes: 24 });

    expect(salt).toEqual('AAAAAAAAAAAAAAAAAAAAAA==');
    expect(hash).toEqual(
      encode(new Uint8Array([24, 27, 61, 130, 166, 76, 158, 118, 62, 106, 57, 57, 176, 85, 85, 199, 154, 35, 41, 53, 29, 249, 240, 0]))
    );
  });

  it('hashPassword creates hash from password, using given salt.', async () => {
    const [salt, hash] = await hashPassword({ password: 'p8ssw0rd!', sizeInBytes: 24, salt: 'givenSalt1234567' });

    expect(salt).toEqual('givenSalt1234567');
    expect(hash).toEqual(
      encode(new Uint8Array([102, 13, 10, 140, 130, 0, 112, 70, 113, 217, 97, 59, 247, 118, 18, 101, 129, 249, 65, 226, 148, 181, 56, 37]))
    );
  });

  describe('constraints', () => {
    it('derivePasswordKey rejects if desired key length is less then 8.', async () => {
      await expect(derivePasswordKey({ sizeInBytes: 7, password: '' })).rejects.toThrow('Invalid key length. Must be at least 8');
    });

    it('hashPassword rejects if desired key length is less then 8.', async () => {
      await expect(hashPassword({ sizeInBytes: 7, password: '' })).rejects.toThrow('Invalid key length. Must be at least 8');
    });

    it('derivePasswordKey rejects if salt length is less then 16.', async () => {
      await expect(derivePasswordKey({ sizeInBytes: 12, password: '', salt: 'too-short123456' })).rejects.toThrow(
        'Invalid salt length. Must be at least 16'
      );
    });

    it('hashPassword rejects if salt length is less then 16.', async () => {
      await expect(hashPassword({ sizeInBytes: 12, password: '', salt: 'too-short123456' })).rejects.toThrow(
        'Invalid salt length. Must be at least 16'
      );
    });
  });
});
