# Changelog

## v0.1.1 2026-02-21

### !!BREAKING CHANGES!!
(see fixes)

### Fixes:
* Fixes wrapKey: keys longer then 32 bytes aren't supported by native web crypto API. \
  web crypto API limits key lengths for aes-key-wrap to 16, 24 or 32 bytes,
  so multiple keys are wrapped separately now and error messages are improved

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