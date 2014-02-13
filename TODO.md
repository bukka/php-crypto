# TODO list

## Internal issues
- add open_basedir check
- memleak for $cipher->encryptUpdate(...) . fceThrowingExc();
- Hash::update returns copy of object (check if data are not copied)
- why SEEK_CUR is 0 when passed to crypto_stream_seek?
  - it should be 1 otherwise it's the same as SEEK_SET which is the only allowed value for cryto.file
		
## Exception
- more OO - add more classes and better structure (class diagram)
  - fix test
- add messages to one place (struct mapping codes and messages)
- replace variadic macros

## BIO
- new streams
  - connect
  - fd
  - socket
- persistent connection

## Base64
- Memory testing
- Why does decodeFinish always return empty string?
- Find an input string that leads to the `Base64Exception` with code `DECODE_FAIL`

## Cipher

#### API
- setting input and output stream based filters (hex, base64...)

#### Features
- Key generation (PKCS#7, PKCS#5)
- Improved list of all algorithms - show just once (currently lc, uc [aes, AES])

#### Not used OpenSSL functions
- `int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)` -- just few options
- `int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)`


## Hash

### API
- improve API doc for HMAC and CMAC
```
class Crypto\CMAC extends Crypto\Hash { /* methods description */ }
class Crypto\HMAC extends Crypto\Hash { /* methods description */ }
```

### Not used OpenSSL functions
- `int EVP_MD_type(const EVP_MD *md)`
- `int EVP_MD_pkey_type(const EVP_MD *md)`

## X509
- Iterator based class
- ASN.1 elements - namespace `Crypto\ASN1`


# Upcoming releases

## 0.2.0 (devel)
- crypto stream
  - BIO wrapper
- improved exceptions

## 0.3.0 (devel)
- ASN.1 classes
- X.509 classes
