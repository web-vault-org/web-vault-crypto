import crypto from 'crypto';
import { encrypt, decrypt } from '@/asymmetric/encryption';

describe('encryption', () => {
  let publicKeyPem1: string;
  let privateKeyPem1: string;
  let publicKeyPem2: string;
  let privateKeyPem2: string;

  async function generateRsaKeyPair() {
    const keyPair = await crypto.webcrypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );

    const publicKeyBuffer = await crypto.webcrypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKeyBuffer = await crypto.webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const toPem = (buffer: ArrayBuffer, type: string) => {
      const base64 = Buffer.from(buffer).toString('base64');
      const formatted = base64.match(/.{1,64}/g)?.join('\n');
      return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
    };

    return {
      publicKey: toPem(publicKeyBuffer, 'PUBLIC KEY'),
      privateKey: toPem(privateKeyBuffer, 'PRIVATE KEY')
    };
  }

  beforeAll(async () => {
    const pair1 = await generateRsaKeyPair();
    const pair2 = await generateRsaKeyPair();

    publicKeyPem1 = pair1.publicKey;
    privateKeyPem1 = pair1.privateKey;

    publicKeyPem2 = pair2.publicKey;
    privateKeyPem2 = pair2.privateKey;
  });

  it('should encrypt and decrypt with single recipient.', async () => {
    const plaintext = 'Hello Johanna 👋';

    const encrypted = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1],
      encode: true
    });
    const decrypted = await decrypt({
      content: encrypted,
      privateKey: privateKeyPem1,
      keyIndex: 0,
      asString: true
    });

    expect(typeof encrypted).toBe('string');
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt for multiple recipients.', async () => {
    const plaintext = 'Shared secret';

    const encrypted = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1, publicKeyPem2],
      encode: false
    });
    const decrypted1 = await decrypt({
      content: encrypted,
      privateKey: privateKeyPem1,
      keyIndex: 1,
      asString: true
    });
    const decrypted2 = await decrypt({
      content: encrypted,
      privateKey: privateKeyPem2,
      keyIndex: 2,
      asString: true
    });

    expect(decrypted1).toBe(plaintext);
    expect(decrypted2).toBe(plaintext);
  });

  it('should fail with wrong private key.', async () => {
    const plaintext = 'Top secret';

    const encrypted = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1]
    });

    await expect(
      decrypt({
        content: encrypted,
        privateKey: privateKeyPem2, // wrong key
        keyIndex: 0,
        asString: true
      })
    ).rejects.toThrow();
  });

  it('should respect additional authenticated data (AAD).', async () => {
    const plaintext = 'Authenticated content';

    const encrypted = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1],
      additionalData: ['context', 'v1']
    });
    const decrypted = await decrypt({
      content: encrypted,
      privateKey: privateKeyPem1,
      keyIndex: 0,
      asString: true,
      additionalData: ['context', 'v1']
    });

    expect(decrypted).toBe(plaintext);
    await expect(
      decrypt({
        content: encrypted,
        privateKey: privateKeyPem1,
        keyIndex: 0,
        asString: true,
        additionalData: ['wrong']
      })
    ).rejects.toThrow();
  });

  it('should produce different ciphertexts for same plaintext.', async () => {
    const plaintext = 'Same message';

    const encrypted1 = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1]
    });
    const encrypted2 = await encrypt({
      content: plaintext,
      publicKeys: [publicKeyPem1]
    });

    expect(encrypted1).not.toEqual(encrypted2);
  });
});
