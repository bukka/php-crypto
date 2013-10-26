# TODO list

## Base64
- Test clone
- Memory testing
- Why does decodeFinish always return empty string?
- Find an input string that leads to the Base64Exception with code DECODE_FAIL

## Cipher

#### API
- Extended constructor: `function __construct($algorithm_name, $mode = null, $extra_ident = null)`
- Static cipher factories: `Cipher::__callStatic($name, $arguments)`
  - `$name` - Algorithm name (e.g. aes...)
  - `$arguments` - array: `$mode` (required), `$extra_ident` (optiona)
  - example: `Cipher::aes(Cipher::MODE_CBC, 128)`

#### Features
- AAD and tags for GCM and CCM modes
- Key generation (PKCS#7, PKCS#5)
- Improved list of all algorithms - show just once (currently lc, uc [aes, AES])

#### Not used OpenSSL functions
- int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
- int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
- int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)


## Hash

### API
```php
class Crypto\Hash extends Crypto\Algorithm {
  function __construst($algorithm_name) {}

  /**
   * New static constructors
   * Example: Hash::md5("data")->digest() = Hash::md5()->update("data")->digest() = (new Hash('md5'))->update("data")->digest()
   * @param string $name Algorithm name (e.g. md5, sha224...)
   * @param array $argument - can contain string data argument as a first item
   */
  function __callStatic($name, $arguments) {}

  function update($data) {}
  function digest() {}
  function hexdigest() {}
  function getSize() {}
  function getBlockSize() {}
}

class Crypto\CMAC extends Crypto\Hash {}
class Crypto\HMAC extends Crypto\Hash {}
```

### Not used OpenSSL functions
- int EVP_MD_type(const EVP_MD *md)
- int EVP_MD_pkey_type(const EVP_MD *md)


## X509
- Iterator based class
