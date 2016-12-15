# Release history

## 0.3.1 (devel)
- Fixed segfault on PHP 5 in setting KDF key length and PBKDF2 iterations

## 0.3.0 (devel)
- Fixed compilation with OpenSSL 1.1 and PHP 7.1
- Added KDF abstract class to be a parent for all key derivation function classes
- Added PBKDF2 class extending KDF class and implementing PBKDF2
- Renamed HashException code ALGORITHM_NOT_FOUND to HASH_ALGORITHM_NOT_FOUND
- Renamed MACException code ALGORITHM_NOT_FOUND to MAC_ALGORITHM_NOT_FOUND

## 0.2.2 (devel)
- Fixed missing CCM cipher algorithms with OpenSSL 1.0.1

## 0.2.1 (devel)
- Fixed C89 compatibility issue in Base64

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
- Added new error code for failed tag verification (TAG_VERIFY_FAILED)
- Add setTagLength Cipher method replacing length param in getTag
- Removed Rand::egd
- Created a complete API documentation

## 0.1.1 (devel)
- Added linking of openssl shared lib to the config.m4
- Fixed buffer overflow in Base64 encoding

## 0.1.0 (devel)
- Cipher
  - incremental encryption & decryption (context methods)
  - cipher info methods (block size, key and iv length...)
  - flexible setting of cipher algorithm (__callStatic)
  - mode setting
  - authentication (GCM and CCM) - AAD setter & auth tag setter and getter
- Hash
  - increments creation of message digest
  - flexible setting of digest algorithm (__callStatic)
- Message authentication codes
  - HMAC and CMAC as subclasses of Hash
- Rand
 - CSPRNG methods
 - seeding methods
 - methods for saving and retrieving PRNG status
- Base64
  - incremental updating (context methods)
  - automatic wrapping rows (suitable for encoding and decoding certificates)
- Exception classes
  - AlgorithmException (for all Cipher and Hash exceptions)
  - Base64Exception


