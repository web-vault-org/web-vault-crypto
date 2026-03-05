import { hash, Argon2BrowserHashOptions, Argon2BrowserHashResult } from 'argon2-browser';

const getArgon2Hash = function (): (options: Argon2BrowserHashOptions) => Promise<Argon2BrowserHashResult> {
  return hash;
};

export { getArgon2Hash };
