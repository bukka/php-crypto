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
- Throw an exception if EVP_DecodeFinal fails
  - the test needs to be found and output should be checked
- Try to add an options for not wrapped output
  - maybe something similar that base64 BIO does


## Cipher
- Limit algorithm name len
- Imrove AEAD
  - add new error code when CCM is called twice
  - use new flag for pre-setting tag (instead of re-using `auth_inlen_init`)
  - rename `auth_enc` to `aead`
  - double check a reason of failed tag verification (try OpenSSL last error)
  - add support for new AEAD modes added in OpenSSL 1.1
- Add new Cipher class constants for tag max and min length
  - Don't forget to update docs
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
  - It's just for PHP 5 (no memleak in 7)

## KDF
- Add new class KDF for Key derivation function
  - EVP_BytesToKey
- Add KDF subclass for PBKDF2
- Add support for scrypt
  - EVP_PBE_scrypt

## Hash
- Test context for Hash, HMAC and CMAC resuming
  - it happens when calling `update` after `digest`
- Add verification function for Hash
- Add method for getting MD type (use `EVP_MD_type`)
- Hash::update returns copy of object (check if data are not copied)
  - it would be better to return the same object and just add ref
  - this is probably just for PHP 5 as it is correct on PHP 7
- Find out and document when the hash `digest` resp. `hexdigest` throws exc

## Rand
- Check if file supplied in Rand::loadFile exists and is readable
- Check if file supplied in Rand::loadFile can be written
- Add open_basedir check
  - `Rand::loadFile`
  - `Rand::writeFile`
- Sort out thread safety for Linux TS build
  - Add locks using CRYPTO_set_locking_callback
- Resolve a locking issue with OpenSSL Rand on Windows
  - maybe it could use php_win32_get_random_bytes
  - http://lxr.php.net/xref/PHP_5_6/win32/winutil.c#80

## Build
- Remove build dependency on openssl ext
- Version check for minimum version
  - At least 0.9.8 should be used

## General
- Consider shorter prefix than `php_crypto`
  - `pce` (Php Crypto Extension)
  - `pcw` (Php Crypto Wrapper)
  - `pcg` (Php CryptoGraphy)
  - `pct` (Php CrypTo or later maybe Php Crypto Tls)
  - `pcr` (Php CRypto)
- Clear OpenSSL errors
  - Separate OpenSSL emitted errors and PHP Crypto extenstion errors
- Add file for utility functions
  - Containing `{prefix}_strtoupper_dup` for algorithm name conversion
- Add Travis support
- Improve overflow handling
  - try inline the functions (make sure it works on Travis)
  - test all overflow checks on PHP 7 (skip PHP 5) 32 and 64 bit
- Add tests for algorithm name arg variable chenging
  - it used to uppercase a string in passed variable
  - it's been fixed but there are no test for that

# Plan for upcoming releases

## 0.3.0 (devel)
- New API for KDF and PBE
- Added verification function for Hash
- Added open_basedir check for Rand::loadFile and Rand::writeFile

