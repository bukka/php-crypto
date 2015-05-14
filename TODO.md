# TODO list

## BIO
- Add new streams
  - connect
  - fd
  - socket
- Add support for persistent connection
- Why SEEK_CUR is 0 when passed to crypto_stream_seek?
  - it should be 1 otherwise it's the same as SEEK_SET which is the only allowed value for cryto.file
- Add crypto PHP stream filters

## Base64
- int overflow check for 7
  - php_crypto_base64_encode_update::inl
  - php_crypto_base64_decode_update::inl
- Memory testing
- Why does decodeFinish always return empty string?
- Find an input string that leads to the `Base64Exception` with code `DECODE_FAIL`

## Cipher
- phpc compat
  - Algorithm read algorithm property
  - Cipher::__callStatic
- int overflow check for 7
  - php_crypto_cipher_update::data_len
  - php_crypto_cipher_crypt::data_len
- limit algorithm name len
- Rename `auth_enc` to `aead`
- CCM plaintext/ciphertext length must be passed
- Auth tag verification error - it's CipherException::FINISH_FAILED atm.
  - is it possible to find out the reason of failing (try OpenSSL last error)
- Add KDF parameter to encryptInit and encrypt
- Add support for `EVP_CIPHER_CTX_rand_key`
- Improved list of all algorithms - show just once (currently lc, uc [aes, AES])
- Setting input and output stream based filters (hex, base64...)
- Fix memleak for $cipher->encryptUpdate(...) . fceThrowingExc();
- Separate code from alg

## KDF
- Add new class KDF for Key derivation function
  - EVP_BytesToKey
- Add KDF subclass for PBKDF2

## Hash
- phpc compat
  - Hash::__callStatic
  - Hash::update (check ZVAL_ZVAL)
- int overflow check for 7
  - php_crypto_hash_update::data_len
- Add method for getting MD type (use `EVP_MD_type`)
- Hash::update returns copy of object (check if data are not copied)
  - it would be better to return the same object and just add ref
- Separate code from alg

## Rand
- Check for overflow in `Rand::generate::buf_len` (positive int is required)
- Check for overflow in `Rand::loadFile::max_bytes` (positive long or -1 is required?)
- Add open_basedir check
  - `Rand::loadFile`
  - `Rand::writeFile`
  - `Rand::egd`

## Internal issues
- Add compatibility layer for PHP 7

## Build
- Add EGD check (LibreSSL compat)
- Version check for minimum version
  - At least 0.9.8 should be used

# Upcoming releases

## 0.2.0 (devel)
- Crypto stream
  - BIO wrapper
- Improved error handling
- Support for PHP 7

## 0.3.0 (devel)
- New API for KDF

