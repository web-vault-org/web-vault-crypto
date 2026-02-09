const getCrypto = async function (): Promise<Crypto> {
  if (typeof window !== 'undefined' && window.crypto) {
    // Browser
    return window.crypto;
  } else {
    // Node.js
    const nodeCrypto = await import('crypto');
    return nodeCrypto.webcrypto as unknown as Crypto;
  }
};

export { getCrypto };
