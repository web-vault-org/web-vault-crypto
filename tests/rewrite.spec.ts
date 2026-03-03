import { rewriteEncryptionHeader } from '@/rewrite';
import { encrypt as encryptSymmetric, decrypt as decryptSymmetric } from '@/symmetric/encryption';
import { encrypt as encryptAsymmetric, decrypt as decryptAsymmetric } from '@/asymmetric/encryption';
import { createEncryptionKeyPair } from '@/asymmetric/createKeyPair';

const encoder = new TextEncoder();

describe('rewriteEncryptionHeader', () => {
  const plaintext = 'top secret message';

  const symmetricKey1 = encoder.encode('12345678901234567890123456789012');
  const symmetricKey2 = encoder.encode('abcdefghijklmnopqrstuvwxzy123456');

  let rsaPair1: { publicKey: string; privateKey: string };
  let rsaPair2: { publicKey: string; privateKey: string };

  beforeAll(async () => {
    rsaPair1 = await createEncryptionKeyPair();
    rsaPair2 = await createEncryptionKeyPair();
  });

  describe('symmetric → symmetric', () => {
    it('should rewrite header to new symmetric key.', async () => {
      const encrypted = await encryptSymmetric({
        content: plaintext,
        key: symmetricKey1
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: symmetricKey1,
        newKey: symmetricKey2
      });

      const decrypted = await decryptSymmetric({
        content: rewritten,
        key: symmetricKey2,
        asString: true
      });
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('symmetric → asymmetric', () => {
    it('should rewrite header from symmetric to RSA, single key.', async () => {
      const encrypted = await encryptSymmetric({
        content: plaintext,
        key: symmetricKey1
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: symmetricKey1,
        newKey: [rsaPair1.publicKey]
      });

      const decrypted = await decryptAsymmetric({
        content: rewritten,
        privateKey: rsaPair1.privateKey,
        keyIndex: 1,
        asString: true
      });
      expect(decrypted).toBe(plaintext);
    });

    it('should rewrite header from symmetric to RSA, multiple keys.', async () => {
      const encrypted = await encryptSymmetric({
        content: plaintext,
        key: symmetricKey1
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: symmetricKey1,
        newKey: [rsaPair1.publicKey, rsaPair2.publicKey]
      });

      const decrypted1 = await decryptAsymmetric({
        content: rewritten,
        privateKey: rsaPair1.privateKey,
        keyIndex: 1,
        asString: true
      });
      const decrypted2 = await decryptAsymmetric({
        content: rewritten,
        privateKey: rsaPair2.privateKey,
        keyIndex: 2,
        asString: true
      });
      expect(decrypted1).toBe(plaintext);
      expect(decrypted2).toBe(plaintext);
    });
  });

  describe('asymmetric → symmetric', () => {
    it('should rewrite header from RSA to symmetric.', async () => {
      const encrypted = await encryptAsymmetric({
        content: plaintext,
        publicKeys: [rsaPair1.publicKey]
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: rsaPair1.privateKey,
        newKey: symmetricKey1,
        keyIndex: 1
      });

      const decrypted = await decryptSymmetric({
        content: rewritten,
        key: symmetricKey1,
        asString: true
      });
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('asymmetric → asymmetric', () => {
    it('should rewrite header to different RSA key.', async () => {
      const encrypted = await encryptAsymmetric({
        content: plaintext,
        publicKeys: [rsaPair1.publicKey]
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: rsaPair1.privateKey,
        newKey: [rsaPair2.publicKey],
        keyIndex: 1
      });

      const decrypted = await decryptAsymmetric({
        content: rewritten,
        privateKey: rsaPair2.privateKey,
        keyIndex: 1,
        asString: true
      });
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('base64 input/output preservation', () => {
    it('should preserve base64 format when input is string.', async () => {
      const encrypted = await encryptSymmetric({
        content: plaintext,
        key: symmetricKey1,
        encode: true
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: symmetricKey1,
        newKey: symmetricKey2
      });

      expect(typeof encrypted).toBe('string');
      expect(typeof rewritten).toBe('string');
    });

    it('should preserve binary format when input is binary.', async () => {
      const encrypted = await encryptSymmetric({
        content: plaintext,
        key: symmetricKey1
      });

      const rewritten = await rewriteEncryptionHeader({
        content: encrypted,
        oldKey: symmetricKey1,
        newKey: symmetricKey2
      });

      expect(encrypted).toBeInstanceOf(Uint8Array);
      expect(rewritten).toBeInstanceOf(Uint8Array);
    });
  });
});
