import { getArgon2Hash } from '@/argon2';
import { createKey } from '@/createKey';
import { encode } from '@/base64';
import { getCrypto } from '@/crypto';
import { importKey } from '@/util';

const createNewSalt = async function () {
  const key = await createKey({ sizeInBytes: 16 });
  return encode(key);
};

const createHashArgon2id = async function ({
  password,
  sizeInBytes,
  salt
}: {
  password: string;
  sizeInBytes: number;
  salt: string;
}): Promise<[string, Uint8Array]> {
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

const createHashPbkdf2 = async function ({
  password,
  sizeInBytes,
  salt
}: {
  password: string;
  sizeInBytes: number;
  salt: string;
}): Promise<[string, Uint8Array]> {
  const crypto = getCrypto();
  const encoder = new TextEncoder();

  const keyMaterial = await importKey(encoder.encode(password), 'PBKDF2', ['deriveBits'], false);
  const saltBytes = encoder.encode(salt);

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 1_000_000,
      hash: 'SHA-256'
    },
    keyMaterial,
    sizeInBytes * 8
  );

  const hash = new Uint8Array(derivedBits);

  return [salt, hash];
};

/**
 * derives key from password
 * @param password - password to derive the key from
 * @param sizeInBytes - desired key size in bytes
 * @param type - type of hashing, argon2id or pbkdf2, default: argon2id
 * @param salt - salt as string (optional, new random salt will be used if not provided)
 * @returns Promise with array containing: salt as string, desired key as Uint8Array
 */
const derivePasswordKey = async function ({
  password,
  sizeInBytes,
  type,
  salt
}: {
  password: string;
  sizeInBytes: number;
  type?: 'argon2id' | 'pbkdf2';
  salt?: string;
}): Promise<[string, Uint8Array]> {
  if (sizeInBytes < 8) {
    throw new Error('Invalid key length. Must be at least 8');
  }

  salt = salt || (await createNewSalt());

  if (salt.length < 16) {
    throw new Error('Invalid salt length. Must be at least 16');
  }

  if (!type || type === 'argon2id') {
    return await createHashArgon2id({ password, salt, sizeInBytes });
  }
  return await createHashPbkdf2({ password, salt, sizeInBytes });
};

/**
 * hashes password
 * @param password - password to hash
 * @param sizeInBytes - desired hash size in bytes
 * @param type - type of hashing, argon2id or pbkdf2, default: argon2id
 * @param salt - salt as string (optional, new random salt will be used if not provided)
 * @returns Promise with array containing: salt as string, hash as base64-encoded string
 */
const hashPassword = async function ({
  password,
  sizeInBytes,
  type,
  salt
}: {
  password: string;
  sizeInBytes: number;
  type?: 'argon2id' | 'pbkdf2';
  salt?: string;
}): Promise<[string, string]> {
  const [salt_, hash] = await derivePasswordKey({ password, sizeInBytes, type, salt });
  return [salt_, encode(hash)];
};

export { derivePasswordKey, hashPassword };
