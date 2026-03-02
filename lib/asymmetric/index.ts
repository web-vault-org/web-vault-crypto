import { createSigningKeyPair, createEncryptionKeyPair } from './createKeyPair';
import { encrypt, decrypt } from './encryption';
import { sign, verify } from './signing';
import { wrapPrivateSigningKey, unwrapPrivateSigningKey, wrapPrivateEncryptionKey, unwrapPrivateEncryptionKey } from './wrapping';

const exp = {
  createEncryptionKeyPair,
  createSigningKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
  wrapPrivateSigningKey,
  unwrapPrivateSigningKey,
  wrapPrivateEncryptionKey,
  unwrapPrivateEncryptionKey
};

export default exp;

export {
  createEncryptionKeyPair,
  createSigningKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
  wrapPrivateSigningKey,
  unwrapPrivateSigningKey,
  wrapPrivateEncryptionKey,
  unwrapPrivateEncryptionKey
};
