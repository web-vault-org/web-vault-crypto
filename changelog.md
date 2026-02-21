# Changelog

## v0.2.0 2026-02-21

### !!BREAKING CHANGES!!
(see fixes)

### Fixes:
* Fixes wrapKey: keys longer then 32 bytes aren't supported by native web crypto API.
* Flagged encryption: To differentiate between symmetric and asymmetric encryption ciphertext begins with a flag:
  * 0x00 for symmetric
  (this is a preparation for planned feature: asymmetric crypto functions)

### Docs
* Adapts docs to changes

## v0.1.0 2026-02-19

### Features
* adds wrapper for key wrapping of single keys
* adds pbkdf2 as hashing system

### Docs
* improves docs and keywords
* adds changelog

## v0.0.3 2026-02-14
minor improvements before first download

## v0.0.2 2026-02-14
minor improvements before first download

## v0.0.1 2026-02-14
initial version