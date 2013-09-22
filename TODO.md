# TODO list

## General tasks

- Output and input formats
  - base64
  - hex
- X509 binding
  - iterator class

## Cipher tasks

### API
- Static cipher factories: `Cipher::aes($mode, $type)`

### Features
- IV generator
- Key generation (PKCS#7, PKCS#5)
- List of all algorithms

### Missing OpenSSL functions
- int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
- int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
- int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)


## Hash tasks

### API
- Static hash factories: `Hash::sha1()`, `Hash::md5`
  - using __callStatic

## Stream
- crypto stream


### Features
- List of all algorithms

### Missing OpenSSL functions
- int EVP_MD_type(const EVP_MD *md)
- int EVP_MD_pkey_type(const EVP_MD *md)
