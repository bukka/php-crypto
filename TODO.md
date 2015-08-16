# TODO list

## BIO
- Better overflow handling for php_crypto_stream_write
  - Do not silently discard to INT_MAX
- Why SEEK_CUR is 0 when passed to crypto_stream_seek?
  - it should be 1 otherwise it's the same as SEEK_SET which is the only allowed value for cryto.file
- Add new streams
  - connect
  - fd
  - socket
- Add support for persistent connection
- Add crypto PHP stream filters

## Base64
- Memory testing
- Why does decodeFinish always return empty string?
- Find an input string that leads to the `Base64Exception` with code `DECODE_FAIL`

## Cipher
- Limit algorithm name len
- AEAD fixes
  - CCM finalization (verification) is failing
  - test CCM enc and dec with empty AAD
  - add `Cipher::setTagLength` instead of length param in `Cipher::getTag`
  - disallow (throw exc when) setting tag length for CCM after init
  - use new flag for pre-setting tag (instead of re-using `auth_inlen_init`)
  - rename `auth_enc` to `aead`
- Auth tag verification error - it's CipherException::FINISH_FAILED atm.
  - is it possible to find out the reason of failing (try OpenSSL last error)
- Add method for setting padding mode
  - something like `setAutoPadding($auto_padding=true)`
  - using `EVP_CIPHER_CTX_set_padding`
- Add KDF parameter to encryptInit and encrypt
- Add support for `EVP_CIPHER_CTX_rand_key`
- Improved list of all algorithms - show just once (currently lc, uc [aes, AES])
- Review cloning
  - There are some issues for some modes (e.g. gcm and old OpenSSL)
  - Use exception when cloning fails
- Setting input and output stream based filters (hex, base64...)
- Fix memleak for $cipher->encryptUpdate(...) . fceThrowingExc();

## KDF
- Add new class KDF for Key derivation function
  - EVP_BytesToKey
- Add KDF subclass for PBKDF2

## Hash
- Test context for Hash, HMAC and CMAC resuming
  - it happens when calling `update` after `digest`
- Add verification function for Hash
- Consider using the same allocator
  - CMAC uses `OpenSSL_malloc` allocator and HMAC and hash use `emalloc`
- Add method for getting MD type (use `EVP_MD_type`)
- Hash::update returns copy of object (check if data are not copied)
  - it would be better to return the same object and just add ref
  - this is probably just for PHP 5 as it is correct on PHP 7
- Find out and document when the hash `digest` resp. `hexdigest` throws exc

## Rand
- Drop egd
- Add open_basedir check
  - `Rand::loadFile`
  - `Rand::writeFile`

## Build
- Remove build dependency on openssl ext
- Version check for minimum version
  - At least 0.9.8 should be used

## General
- Create `php_crypto_strtoupper_dup` for algorithm name conversion
- Consider shorter prefix than `php_crypto`
  - `pce` (Php Crypto Extension)
  - `pcw` (Php Crypto Wrapper)
  - `pcg` (Php CryptoGraphy)
  - `pct` (Php CrypTo or later maybe Php Crypto Tls)
  - `pcr` (Php CRypto)
- Test all overflow check on PHP 7 (skip PHP 5)
- Add tests for algorithm name arg variable chenging
  - it used to uppercase a string in passed variable
  - it's been fixed but there are no test for that

# Plan for upcoming releases

## 0.2.0 (devel)
- Support for PHP 7
- Crypto stream BIO wrapper
- Improved error handling
- Added an integer overflow checking
- Removed Algorithm class and AlogirithmException class
- Introduced a MAC class as a subclass of Hash and parent of HMAC and CMAC
- Added MACException class subclassing HashException
- Fixed HMAC and CMAC implementation and added key param to constructor
- Fixed and tested CCM mode
- Add setTagLength Cipher method replacing length param in getTag
- Removed Rand::egd
- Created a complete API documentation

## 0.3.0 (devel)
- New API for KDF
- Added verification function for Hash
- Added open_basedir check for Rand::loadFile and Rand::writeFile

