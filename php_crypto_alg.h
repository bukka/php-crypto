/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Jakub Zelenka <jakub.php@gmail.com>                          |
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
	PHP_CRYPTO_ALG_STATUS_ENCRYPT_DONE,
	PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT,
	PHP_CRYPTO_ALG_STATUS_DECRYPT_DONE,
} php_crypto_algorithm_status;

typedef struct {
	zend_object zo;
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
		} cipher;
		struct {
			const EVP_MD *alg;
			union {
				EVP_MD_CTX *md;
				HMAC_CTX *hmac;
			} ctx;
		} hash;
	} evp;
} php_crypto_algorithm_object;

/* Algorithm object accessors */
#define PHP_CRYPTO_CIPHER_CTX(pobj) (pobj)->evp.cipher.ctx.cipher
#define PHP_CRYPTO_CIPHER_ALG(pobj) (pobj)->evp.cipher.alg
#ifdef PHP_CRYPTO_HAS_CMAC
#define PHP_CRYPTO_CMAC_CTX(pobj) (pobj)->evp.cipher.ctx.cmac
#define PHP_CRYPTO_CMAC_ALG PHP_CRYPTO_CIPHER_ALG
#endif
#define PHP_CRYPTO_HASH_CTX(pobj) (pobj)->evp.hash.ctx.md
#define PHP_CRYPTO_HASH_ALG(pobj) (pobj)->evp.hash.alg
#define PHP_CRYPTO_HMAC_CTX(pobj)   (pobj)->evp.hash.ctx.hmac
#define PHP_CRYPTO_HMAC_ALG PHP_CRYPTO_HASH_ALG

/* Algorithm exceptions macros */
#define PHP_CRYPTO_ALG_E(code) PHP_CRYPTO_ALGORITHM_ERROR_##code
#define PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(code, msg) \
	PHP_CRYPTO_THROW_EXCEPTION(php_crypto_algorithm_exception_ce, PHP_CRYPTO_ALG_E(code), msg)
#define PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(code, msg, ...) \
	PHP_CRYPTO_THROW_EXCEPTION_EX(php_crypto_algorithm_exception_ce, PHP_CRYPTO_ALG_E(code), msg, ##__VA_ARGS__)

/* Algorithm exception error codes */
typedef enum {
	PHP_CRYPTO_ALG_E(CIPHER_NOT_FOUND) = 1,
	PHP_CRYPTO_ALG_E(CIPHER_MODE_NOT_FOUND),
	PHP_CRYPTO_ALG_E(CIPHER_MODE_NOT_AVAILABLE),
	PHP_CRYPTO_ALG_E(CIPHER_AUTHENTICATION_NOT_SUPPORTED),
	PHP_CRYPTO_ALG_E(CIPHER_AUTHENTICATION_FAILED),
	PHP_CRYPTO_ALG_E(CIPHER_KEY_LENGTH),
	PHP_CRYPTO_ALG_E(CIPHER_IV_LENGTH),
	PHP_CRYPTO_ALG_E(CIPHER_AAD_FLOW),
	PHP_CRYPTO_ALG_E(CIPHER_TAG_FLOW),
	PHP_CRYPTO_ALG_E(CIPHER_INIT_FAILED),
	PHP_CRYPTO_ALG_E(CIPHER_UPDATE_FAILED),
	PHP_CRYPTO_ALG_E(CIPHER_FINISH_FAILED),
	PHP_CRYPTO_ALG_E(ENCRYPT_INIT_STATUS),
	PHP_CRYPTO_ALG_E(ENCRYPT_UPDATE_STATUS),
	PHP_CRYPTO_ALG_E(ENCRYPT_FINISH_STATUS),
	PHP_CRYPTO_ALG_E(DECRYPT_INIT_STATUS),
	PHP_CRYPTO_ALG_E(DECRYPT_UPDATE_STATUS),
	PHP_CRYPTO_ALG_E(DECRYPT_FINISH_STATUS),
	PHP_CRYPTO_ALG_E(HASH_ALGORITHM_NOT_FOUND),
	PHP_CRYPTO_ALG_E(HASH_STATIC_NOT_FOUND),
	PHP_CRYPTO_ALG_E(HASH_INIT_FAILED),
	PHP_CRYPTO_ALG_E(HASH_UPDATE_FAILED),
	PHP_CRYPTO_ALG_E(HASH_DIGEST_FAILED)
} php_crypto_algorithm_error_code;

/* Mode string length */
#define PHP_CRYPTO_CIPHER_MODE_LEN 3

/* Cipher mode lookup table entry struct */
typedef struct {
	const char name[PHP_CRYPTO_CIPHER_MODE_LEN+1];
	const char constant[PHP_CRYPTO_CIPHER_MODE_LEN+6];
	long value;
	zend_bool auth_enc; /* authenticated encryption */
} php_crypto_cipher_mode;

/* Constant value for cipher mode that is not implemented (when using old version of OpenSSL) */
#define PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED -1

/* Macros for cipher mode lookup table */
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(mode_name, mode_auth_enc) { #mode_name, "MODE_" #mode_name, EVP_CIPH_ ## mode_name ## _MODE, mode_auth_enc },
#define PHP_CRYPTO_CIPHER_MODE_ENTRY(mode_name) PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(mode_name, 0)
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(mode_name) { #mode_name, "MODE_" #mode_name, PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED, 0 },
#define PHP_CRYPTO_CIPHER_MODE_ENTRY_END { "", "", 0 }


/* CLASSES */

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_exception_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hash_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hmac_ce;
#ifdef PHP_CRYPTO_HAS_CMAC
extern PHP_CRYPTO_API zend_class_entry *php_crypto_cmac_ce;
#endif


/* METHODS */

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

#endif	/* PHP_CRYPTO_EVP_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
