import { arrayBufferToPem, pemToArrayBuffer, validatePrivateSigningKey } from '@/asymmetric/util';
import { encrypt, decrypt } from '@/symmetric';

const wrapPrivateSigningKey = async function ({ privateSigningKey, key }: { privateSigningKey: string; key: Uint8Array }): Promise<string> {
  validatePrivateSigningKey(privateSigningKey);
  const dataArrayBuffer = pemToArrayBuffer(privateSigningKey);
  const content = new Uint8Array(dataArrayBuffer);
  return (await encrypt({ content, key, encode: true, additionalData: ['privateSigningKey'] })) as string;
};

const unwrapPrivateSigningKey = async function ({
  wrappedPrivateSigningKey,
  key
}: {
  wrappedPrivateSigningKey: string;
  key: Uint8Array;
}): Promise<string> {
  const content = (await decrypt({ content: wrappedPrivateSigningKey, key, additionalData: ['privateSigningKey'] })) as Uint8Array;
  const dataArrayBuffer = content.buffer;
  return arrayBufferToPem(dataArrayBuffer, 'PRIVATE KEY');
};

export { wrapPrivateSigningKey, unwrapPrivateSigningKey };
