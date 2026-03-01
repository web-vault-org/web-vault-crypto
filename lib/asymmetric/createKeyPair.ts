import { getCrypto } from '@/crypto';
import { arrayBufferToPem } from '@/asymmetric/util';

interface KeyPairPem {
  publicKey: string;
  privateKey: string;
}

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

export { createSigningKeyPair };
