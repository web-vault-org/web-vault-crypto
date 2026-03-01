import {
  createKey,
  derivePasswordKey,
  hashPassword,
  wrapKeys,
  unwrapKeys,
  encrypt as encryptSymmetric,
  decrypt as decryptSymmetric,
  sign as signSymmetric,
  verify as verifySymmetric
} from '@/symmetric';
import {
  createEncryptionKeyPair,
  createSigningKeyPair,
  encrypt as encryptAsymmetric,
  decrypt as decryptAsymmetric,
  sign as signAsymmetric,
  verify as verifyAsymmetric,
  wrapPrivateSigningKey,
  unwrapPrivateSigningKey,
  wrapPrivateEncryptionKey,
  unwrapPrivateEncryptionKey
} from '@/asymmetric';

const exp = {
  createKey,
  derivePasswordKey,
  hashPassword,
  wrapKeys,
  unwrapKeys,
  encryptSymmetric,
  decryptSymmetric,
  signSymmetric,
  verifySymmetric,
  createEncryptionKeyPair,
  createSigningKeyPair,
  encryptAsymmetric,
  decryptAsymmetric,
  signAsymmetric,
  verifyAsymmetric,
  wrapPrivateSigningKey,
  unwrapPrivateSigningKey,
  wrapPrivateEncryptionKey,
  unwrapPrivateEncryptionKey,
  encrypt: encryptSymmetric,
  decrypt: decryptSymmetric,
  sign: signSymmetric,
  verify: verifySymmetric
};

export default exp;

export {
  createKey,
  derivePasswordKey,
  hashPassword,
  wrapKeys,
  unwrapKeys,
  encryptSymmetric,
  decryptSymmetric,
  signSymmetric,
  verifySymmetric,
  createEncryptionKeyPair,
  createSigningKeyPair,
  encryptAsymmetric,
  decryptAsymmetric,
  signAsymmetric,
  verifyAsymmetric,
  wrapPrivateSigningKey,
  unwrapPrivateSigningKey,
  wrapPrivateEncryptionKey,
  unwrapPrivateEncryptionKey,
  encryptSymmetric as encrypt,
  decryptSymmetric as decrypt,
  signSymmetric as sign,
  verifySymmetric as verify
};
