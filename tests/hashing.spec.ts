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
  it('derivePasswordKey creates key from password, using new salt.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24 });

    expect(salt).toEqual('AAAAAAAAAAAAAAAAAAAAAA==');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(new Uint8Array([24, 27, 61, 130, 166, 76, 158, 118, 62, 106, 57, 57, 176, 85, 85, 199, 154, 35, 41, 53, 29, 249, 240, 0]));
  });

  it('derivePasswordKey creates key from password, using given salt.', async () => {
    const [salt, key] = await derivePasswordKey({ password: 'p8ssw0rd!', sizeInBytes: 24, salt: 'givenSalt' });

    expect(salt).toEqual('givenSalt');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(24);
    expect(key).toEqual(
      new Uint8Array([150, 18, 92, 142, 158, 233, 71, 53, 84, 159, 186, 179, 60, 67, 184, 35, 231, 221, 88, 206, 15, 129, 170, 218])
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
    const [salt, hash] = await hashPassword({ password: 'p8ssw0rd!', sizeInBytes: 24, salt: 'givenSalt' });

    expect(salt).toEqual('givenSalt');
    expect(hash).toEqual(
      encode(new Uint8Array([150, 18, 92, 142, 158, 233, 71, 53, 84, 159, 186, 179, 60, 67, 184, 35, 231, 221, 88, 206, 15, 129, 170, 218]))
    );
  });
});
