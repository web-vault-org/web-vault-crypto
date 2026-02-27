import { Argon2BrowserHashOptions, Argon2BrowserHashResult } from 'argon2-browser';
import { hash } from 'argon2';

const getArgon2Hash = function (): (options: Argon2BrowserHashOptions) => Promise<Argon2BrowserHashResult> {
  return async function ({ pass, salt, type, time, hashLen, parallelism, mem }: Argon2BrowserHashOptions): Promise<Argon2BrowserHashResult> {
    const saltBuffer = Buffer.from(salt as string, 'utf8');
    const hashEncoded = await hash(pass as string, { salt: saltBuffer, type, timeCost: time, hashLength: hashLen, parallelism, memoryCost: mem });
    const hashBase64 = hashEncoded.split('$').at(-1) as string;
    const hashUint8Array = new Uint8Array(Buffer.from(hashBase64, 'base64'));
    const hashHex = Buffer.from(hashBase64, 'base64').toString('hex');
    return { encoded: hashEncoded, hash: hashUint8Array, hashHex };
  };
};

export { getArgon2Hash };
