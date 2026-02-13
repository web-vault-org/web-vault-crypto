import { getArgon2Hash } from '@/argon2';
import { createKey } from '@/createKey';
import { encode } from '@/base64';

const createNewSalt = async function () {
  const key = await createKey({ sizeInBytes: 16 });
  return encode(key);
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
  if (sizeInBytes < 8) {
    throw new Error('Invalid key length. Must be at least 8');
  }

  salt = salt || (await createNewSalt());

  if (salt.length < 16) {
    throw new Error('Invalid salt length. Must be at least 16');
  }

  const result = await getArgon2Hash()({
    salt,
    pass: password,
    type: 2,
    parallelism: 1,
    hashLen: sizeInBytes,
    time: 2,
    mem: 24_576
  });
  return [salt, result.hash];
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
