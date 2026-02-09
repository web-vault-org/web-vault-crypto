interface WebVault {
  /**
   * generates a random key with desired size.
   * @param sizeInBytes - desired key size in bytes
   * @returns Promise with desired key as Uint8Array
   */
  createKey: ({ sizeInBytes }: { sizeInBytes: number }) => Promise<Uint8Array>;

  /**
   * derives key from password
   * @param password - password to derive the key from
   * @param sizeInBytes - desired key size in bytes
   * @param salt - salt as string (optional, new random salt will be used if not provided)
   * @returns Promise with array containing: salt as string, desired key as Uint8Array
   */
  derivePasswordKey: ({ password, sizeInBytes, salt }: { password: string; sizeInBytes: number; salt?: string }) => Promise<[string, Uint8Array]>;

  /**
   * hashes password
   * @param password - password to hash
   * @param sizeInBytes - desired hash size in bytes
   * @param salt - salt as string (optional, new random salt will be used if not provided)
   * @returns Promise with array containing: salt as string, hash as base64-encoded string
   */
  hashPassword: ({ password, sizeInBytes, salt }: { password: string; sizeInBytes: number; salt?: string }) => Promise<[string, string]>;

  /**
   * wraps/encrypts keys
   * @param keys - keys to wrap/encrypt (length (in bytes) for each key must be multiple of 8)
   * @param kek - key used to encrypt the keys
   * @param encode - boolean, if wrapped keys should be base64-encoded
   * @returns Promise with wrappedKeys, as base64-encoded string if `encode` is true, as Uint8Array if not
   */
  wrapKeys: ({ keys, kek, encode }: { keys: Uint8Array[]; kek: Uint8Array; encode?: boolean }) => Promise<Uint8Array | string>;

  /**
   * unwraps/decrypts keys
   * @param wrappedKeys - keys to unwrap/decrypt
   * @param kek - key used to encrypt the keys
   * @returns Promise with an array of unwrapped keys
   */
  unwrapKeys: ({ wrappedKeys, kek, lengths }: { wrappedKeys: Uint8Array | string; kek: Uint8Array; lengths?: number[] }) => Promise<Uint8Array[]>;

  /**
   * encrypts a string or a Uint8Array
   * @param content - plaintext as string or Uint8Array
   * @param key - key as Uint8Array
   * @param encode - boolean, if plaintext should be base64-encoded
   * @returns Promise with ciphertext, as base64-encoded string if `encode` is true, as Uint8Array if not
   */
  encrypt: ({ content, key, encode }: { content: string | Uint8Array; key: Uint8Array; encode?: boolean }) => Promise<Uint8Array | string>;

  /**
   * decrypts a string or a Uint8Array
   * @param content - ciphertext as string or Uint8Array
   * @param key - key as Uint8Array
   * @param asString - boolean, if plaintext should be returned as string
   * @returns Promise with plaintext, as string if `asString` is true, as Uint8Array if not
   */
  decrypt: ({ content, key, asString }: { content: string | Uint8Array; key: Uint8Array; asString?: boolean }) => Promise<Uint8Array | string>;

  /**
   * signs an object
   * @param data - object to sign
   * @param key - signing key
   * @param exclude - array with names of properties to exclude
   * @returns Promise with signature as base64-encoded string
   */
  sign: ({ data, key, exclude }: { data: object; key: Uint8Array; exclude?: string[] }) => Promise<string>;

  /**
   * verifies an object
   * @param data - object to verify
   * @param key - signing key
   * @param signature - signature as string to verify the object against
   * @param exclude - array with names of properties to exclude
   * @returns Promise with boolean, stating if object is authentic and integer
   */
  verify: ({ data, key, signature, exclude }: { data: object; key: Uint8Array; signature: string; exclude?: string[] }) => Promise<boolean>;
}

export { WebVault };
