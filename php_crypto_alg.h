/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2013-2015 Jakub Zelenka                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Jakub Zelenka <bukka@php.net>                                |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_CRYPTO_ALG_H
#define PHP_CRYPTO_ALG_H

#include "php.h"
#include "php_crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifdef PHP_CRYPTO_HAS_CMAC
#include <openssl/cmac.h>
#endif

typedef enum {
	PHP_CRYPTO_ALG_NONE = 0,
	PHP_CRYPTO_ALG_CIPHER,
	PHP_CRYPTO_ALG_HASH,
	PHP_CRYPTO_ALG_HMAC,
	PHP_CRYPTO_ALG_CMAC
} php_crypto_algorithm_type;

typedef enum {
	PHP_CRYPTO_ALG_STATUS_CLEAR,
	PHP_CRYPTO_ALG_STATUS_HASH,
	PHP_CRYPTO_ALG_STATUS_ENCRYPT_INIT,
	PHP_CRYPTO_ALG_STATUS_ENCRYPT_UPDATE,
	PHP_CRYPTO_ALG_STATUS_ENCRYPT_FINAL,
	PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT,
	PHP_CRYPTO_ALG_STATUS_DECRYPT_UPDATE,
	PHP_CRYPTO_ALG_STATUS_DECRYPT_FINAL
} php_crypto_algorithm_status;

PHPC_OBJ_STRUCT_BEGIN(crypto_alg)
	php_crypto_algorithm_type type;
	php_crypto_algorithm_status status;
	union {
		struct {
			const EVP_CIPHER *alg;
			union {
				EVP_CIPHER_CTX *cipher;
#ifdef PHP_CRYPTO_HAS_CMAC
				CMAC_CTX *cmac;
#endif
			} ctx;
			unsigned char *aad;
			int aad_len;
			unsigned char *tag;
			int tag_len;
		} cipher;
		struct {
			const EVP_MD *alg;
			union {
				EVP_MD_CTX *md;
				HMAC_CTX *hmac;
			} ctx;
		} hash;
	} evp;
PHPC_OBJ_STRUCT_END()
/* php_crypto_algorithm_object -> struct _phpc_crypto_alg__obj */

/* Cipher status accessors */
#define PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(pobj) \
	((pobj)->status == PHP_CRYPTO_ALG_STATUS_ENCRYPT_INIT || (pobj)->status == PHP_CRYPTO_ALG_STATUS_ENCRYPT_UPDATE)
#define PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(pobj) \
	((pobj)->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT || (pobj)->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_UPDATE)
#define PHP_CRYPTO_CIPHER_SET_STATUS(pobj, is_enc, status_name) \
	(pobj)->status = ((is_enc) ? PHP_CRYPTO_ALG_STATUS_ENCRYPT_ ## status_name : PHP_CRYPTO_ALG_STATUS_DECRYPT_ ## status_name)

/* Algorithm object accessors */
#define PHP_CRYPTO_CIPHER_CTX(pobj) (pobj)->evp.cipher.ctx.cipher
#define PHP_CRYPTO_CIPHER_ALG(pobj) (pobj)->evp.cipher.alg
#define PHP_CRYPTO_CIPHER_AAD(pobj) (pobj)->evp.cipher.aad
#define PHP_CRYPTO_CIPHER_AAD_LEN(pobj) (pobj)->evp.cipher.aad_len
#define PHP_CRYPTO_CIPHER_TAG(pobj) (pobj)->evp.cipher.tag
#define PHP_CRYPTO_CIPHER_TAG_LEN(pobj) (pobj)->evp.cipher.tag_len
#ifdef PHP_CRYPTO_HAS_CMAC
#define PHP_CRYPTO_CMAC_CTX(pobj) (pobj)->evp.cipher.ctx.cmac
#define PHP_CRYPTO_CMAC_ALG PHP_CRYPTO_CIPHER_ALG
#endif
#define PHP_CRYPTO_HASH_CTX(pobj) (pobj)->evp.hash.ctx.md
#define PHP_CRYPTO_HASH_ALG(pobj) (pobj)->evp.hash.alg
#define PHP_CRYPTO_HMAC_CTX(pobj)   (pobj)->evp.hash.ctx.hmac
#define PHP_CRYPTO_HMAC_ALG PHP_CRYPTO_HASH_ALG

/* Exceptions */
PHP_CRYPTO_EXCEPTION_EXPORT(Algorithm)
PHP_CRYPTO_EXCEPTION_EXPORT(Cipher)
PHP_CRYPTO_EXCEPTION_EXPORT(Hash)
/* Error infos */
PHP_CRYPTO_ERROR_INFO_EXPORT(Cipher)
PHP_CRYPTO_ERROR_INFO_EXPORT(Hash)

/* Mode string length */
#define PHP_CRYPTO_CIPHER_MODE_LEN 3

/* Cipher mode lookup table entry struct */
typedef struct {
	const char name[PHP_CRYPTO_CIPHER_MODE_LEN+1];
	const char constant[PHP_CRYPTO_CIPHER_MODE_LEN+6];
	long value;
	zend_bool auth_enc; /* authenticated encryption */
	int auth_ivlen_flag;
	int auth_set_tag_flag;
	int auth_get_tag_flag;
} php_crypto_cipher_mode;

/* Constant value for cipher mode that is not implemented (when using old version of OpenSSL) */
#define PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED -1

/* Cipher mode value (EVP code) */
#define PHP_CRYPTO_CIPHER_MODE_VALUE(pobj) EVP_CIPHER_mode(PHP_CRYPTO_CIPHER_ALG(pobj))

/* Macros for cipher mode lookup table */
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(mode_name, mode_auth_enc, mode_auth_ivlen_flag, mode_auth_stag_flag, mode_auth_gtag_flag) \
	{ #mode_name, "MODE_" #mode_name, EVP_CIPH_ ## mode_name ## _MODE, \
	mode_auth_enc, mode_auth_ivlen_flag, mode_auth_stag_flag, mode_auth_gtag_flag },
#define PHP_CRYPTO_CIPHER_MODE_ENTRY(mode_name) PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(mode_name, 0, 0, 0, 0)
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(mode_name) \
	{ #mode_name, "MODE_" #mode_name, PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED, 0, 0, 0, 0 },
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_END { "", "", 0, 0, 0, 0, 0 }

/* Cipher authentication tag length max and min */
#define PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MIN 4
#define PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX 16


/* CLASSES */

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hash_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hmac_ce;
#ifdef PHP_CRYPTO_HAS_CMAC
extern PHP_CRYPTO_API zend_class_entry *php_crypto_cmac_ce;
#endif

/* USER METHODS */

/* Module init for Crypto Algorithm */
PHP_MINIT_FUNCTION(crypto_alg);

/* Algorithm methods */
PHP_CRYPTO_METHOD(Algorithm, __construct);
PHP_CRYPTO_METHOD(Algorithm, getAlgorithmName);
/* Cipher methods */
PHP_CRYPTO_METHOD(Cipher, getAlgorithms);
PHP_CRYPTO_METHOD(Cipher, hasAlgorithm);
PHP_CRYPTO_METHOD(Cipher, hasMode);
PHP_CRYPTO_METHOD(Cipher, __callStatic);
PHP_CRYPTO_METHOD(Cipher, __construct);
PHP_CRYPTO_METHOD(Cipher, encryptInit);
PHP_CRYPTO_METHOD(Cipher, encryptUpdate);
PHP_CRYPTO_METHOD(Cipher, encryptFinish);
PHP_CRYPTO_METHOD(Cipher, encrypt);
PHP_CRYPTO_METHOD(Cipher, decryptInit);
PHP_CRYPTO_METHOD(Cipher, decryptUpdate);
PHP_CRYPTO_METHOD(Cipher, decryptFinish);
PHP_CRYPTO_METHOD(Cipher, decrypt);
PHP_CRYPTO_METHOD(Cipher, getBlockSize);
PHP_CRYPTO_METHOD(Cipher, getKeyLength);
PHP_CRYPTO_METHOD(Cipher, getIVLength);
PHP_CRYPTO_METHOD(Cipher, getMode);
PHP_CRYPTO_METHOD(Cipher, getTag);
PHP_CRYPTO_METHOD(Cipher, setTag);
PHP_CRYPTO_METHOD(Cipher, getAAD);
PHP_CRYPTO_METHOD(Cipher, setAAD);
/* Hash methods */
PHP_CRYPTO_METHOD(Hash, getAlgorithms);
PHP_CRYPTO_METHOD(Hash, hasAlgorithm);
PHP_CRYPTO_METHOD(Hash, __callStatic);
PHP_CRYPTO_METHOD(Hash, __construct);
PHP_CRYPTO_METHOD(Hash, update);
PHP_CRYPTO_METHOD(Hash, digest);
PHP_CRYPTO_METHOD(Hash, hexdigest);
PHP_CRYPTO_METHOD(Hash, getSize);
PHP_CRYPTO_METHOD(Hash, getBlockSize);


/* CRYPTO API FUNCTIONS */
/* Cipher functions  */
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm(
	char *algorithm, int algorithm_len);
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm_from_params(
		char *algorithm, phpc_str_size_t algorithm_len,
		zval *pz_mode, zval *pz_key_size TSRMLS_DC);
PHP_CRYPTO_API const php_crypto_cipher_mode *php_crypto_get_cipher_mode_ex(long mode_value);
PHP_CRYPTO_API const php_crypto_cipher_mode *php_crypto_get_cipher_mode(const EVP_CIPHER *cipher);
PHP_CRYPTO_API int php_crypto_cipher_set_tag(EVP_CIPHER_CTX *cipher_ctx,
		const php_crypto_cipher_mode *mode, unsigned char *tag, int tag_len TSRMLS_DC);
PHP_CRYPTO_API int php_crypto_cipher_write_aad(EVP_CIPHER_CTX *cipher_ctx,
		unsigned char *aad, int aad_len TSRMLS_DC);
/* Hash functions */
PHP_CRYPTO_API void php_crypto_hash_bin2hex(char *out, const unsigned char *in, unsigned in_len);


#endif	/* PHP_CRYPTO_EVP_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
