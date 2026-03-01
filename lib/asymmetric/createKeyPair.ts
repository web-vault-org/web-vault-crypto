import { getCrypto } from '@/crypto';
import { arrayBufferToPem, rsaOaepParams } from '@/asymmetric/util';

interface KeyPairPem {
  publicKey: string;
  privateKey: string;
}

/**
 * Creates an Ed25519 public/private key pair for sign and verify.
 * @returns Promise with the key pair object containing publicKey and privateKey
 */
const createSigningKeyPair = async function (): Promise<KeyPairPem> {
  const crypto = getCrypto();
  const pair = await crypto.subtle.generateKey(
    {
      name: 'Ed25519'
    },
    true,
    ['sign', 'verify']
  );

  const publicKeyBuffer = await crypto.subtle.exportKey('spki', (pair as CryptoKeyPair).publicKey);
  const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', (pair as CryptoKeyPair).privateKey);

  return {
    publicKey: arrayBufferToPem(publicKeyBuffer, 'PUBLIC KEY'),
    privateKey: arrayBufferToPem(privateKeyBuffer, 'PRIVATE KEY')
  };
};

/**
 * Creates an RSA-OAEP public/private key pair for encryption and decryption.
 * @returns Promise with the key pair object containing publicKey and privateKey
 */
const createEncryptionKeyPair = async function (): Promise<KeyPairPem> {
  const crypto = getCrypto();
  const pair = await crypto.subtle.generateKey(rsaOaepParams, true, ['encrypt', 'decrypt']);
  const publicKeyBuffer = await crypto.subtle.exportKey('spki', (pair as CryptoKeyPair).publicKey);
  const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', (pair as CryptoKeyPair).privateKey);
  return {
    publicKey: arrayBufferToPem(publicKeyBuffer, 'PUBLIC KEY'),
    privateKey: arrayBufferToPem(privateKeyBuffer, 'PRIVATE KEY')
  };
};

export { createSigningKeyPair, createEncryptionKeyPair, KeyPairPem };
