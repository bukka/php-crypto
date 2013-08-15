# TODO list

## Missing parameters functions

### Cipher
- int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
- int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
- int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
- int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
- int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
- int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)

### Digest
- int EVP_MD_block_size(const EVP_MD *md)
- int EVP_MD_type(const EVP_MD *md)
- int EVP_MD_pkey_type(const EVP_MD *md)
- int EVP_MD_size(const EVP_MD *md)
