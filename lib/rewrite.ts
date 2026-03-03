import { extract as extractSymmetric, rewrite as rewriteSymmetric } from '@/symmetric/encryption';
import { extract as extractAsymmetric, rewrite as rewriteAsymmetric } from '@/asymmetric/encryption';
import { encode } from '@/base64';

type OldKey = Uint8Array | string;
type NewKey = Uint8Array | string[];

const extract = async function (content: string | Uint8Array, oldKey: OldKey, keyIndex?: number): Promise<[CryptoKey, Uint8Array, Uint8Array]> {
  if (typeof oldKey === 'string') {
    return await extractAsymmetric(content, oldKey, keyIndex ?? 1);
  }
  return await extractSymmetric(content, oldKey);
};

const rewrite = async function (contentKey: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array, newKey: NewKey): Promise<Uint8Array> {
  if ('push' in newKey) {
    return await rewriteAsymmetric(contentKey, iv, ciphertext, newKey);
  }
  return await rewriteSymmetric(contentKey, iv, ciphertext, newKey);
};

const rewriteEncryptionHeader = async function ({
  content,
  oldKey,
  newKey,
  keyIndex
}: {
  content: string | Uint8Array;
  oldKey: OldKey;
  newKey: NewKey;
  keyIndex?: number;
}): Promise<string | Uint8Array> {
  const wasString = typeof content === 'string';
  const [contentKey, iv, ciphertext] = await extract(content, oldKey, keyIndex);
  const rewritten = await rewrite(contentKey, iv, ciphertext, newKey);
  return wasString ? encode(rewritten) : rewritten;
};

export { rewriteEncryptionHeader };
