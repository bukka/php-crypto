# Release history

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


