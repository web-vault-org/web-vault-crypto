'use strict';

import path from 'path';

export default {
  entry: './built/index.js',
  mode: 'production',
  output: {
    path: path.resolve('./', 'dist'),
    filename: 'web-vault-crypto.js',
    globalObject: 'this',
    library: {
      name: 'webVaultCrypto',
      type: 'umd'
    }
  },
  module: {
    noParse: /\.wasm$/,
    rules: [
      {
        test: /\.wasm$/,
        loader: 'base64-loader',
        type: 'javascript/auto'
      }
    ]
  },
  resolve: {
    fallback: {
      path: false,
      fs: false,
      os: false,
      Buffer: false,
      process: false
    },
    fullySpecified: false
  }
};
