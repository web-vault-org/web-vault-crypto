import { createKey } from '@/createKey';
import { encode } from '@/base64';

const createNewSalt = async function () {
  const key = await createKey({ sizeInBytes: 16 });
  return encode(key);
};

const hashWithArgon2Node = async function (password: string, salt: string, sizeInBytes: number): Promise<Uint8Array> {
  const argon2Node = await import('argon2');
  const hashEncoded = await argon2Node.hash(password, {
    salt: Buffer.from(salt, 'utf8'),
    type: 2,
    parallelism: 1,
    hashLength: sizeInBytes,
    timeCost: 2,
    memoryCost: 24_576
  });
  const hashBase64 = hashEncoded.split('$').at(-1) as string;
  return new Uint8Array(Buffer.from(hashBase64, 'base64'));
};

const hashWithArgon2Browser = async function (password: string, salt: string, sizeInBytes: number): Promise<Uint8Array> {
  const argon2Browser = await import('argon2-browser');
  const hashHex = await argon2Browser.hash({
    salt,
    pass: password,
    type: 2,
    parallelism: 1,
    hashLen: sizeInBytes,
    time: 2,
    mem: 24_576
  });
  return hashHex.hash;
};

/**
 * derives key from password
 * @param password - password to derive the key from
 * @param sizeInBytes - desired key size in bytes
 * @param salt - salt as string (optional, new random salt will be used if not provided)
 * @returns Promise with array containing: salt as string, desired key as Uint8Array
 */
const derivePasswordKey = async function ({
  password,
  sizeInBytes,
  salt
}: {
  password: string;
  sizeInBytes: number;
  salt?: string;
}): Promise<[string, Uint8Array]> {
  salt = salt || (await createNewSalt());
  let hash: Uint8Array;
  if (typeof window !== 'undefined') {
    hash = await hashWithArgon2Browser(password, salt, sizeInBytes);
  } else {
    hash = await hashWithArgon2Node(password, salt, sizeInBytes);
  }
  return [salt, hash];
};

/**
 * hashes password
 * @param password - password to hash
 * @param sizeInBytes - desired hash size in bytes
 * @param salt - salt as string (optional, new random salt will be used if not provided)
 * @returns Promise with array containing: salt as string, hash as base64-encoded string
 */
const hashPassword = async function ({
  password,
  sizeInBytes,
  salt
}: {
  password: string;
  sizeInBytes: number;
  salt?: string;
}): Promise<[string, string]> {
  const [salt_, hash] = await derivePasswordKey({ password, sizeInBytes, salt });
  return [salt_, encode(hash)];
};

export { derivePasswordKey, hashPassword };
