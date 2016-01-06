/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2013-2016 Jakub Zelenka                                |
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

#ifndef PHP_CRYPTO_HASH_H
#define PHP_CRYPTO_HASH_H

#include "php.h"
#include "php_crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifdef PHP_CRYPTO_HAS_CMAC
#include <openssl/cmac.h>
#endif

typedef enum {
	PHP_CRYPTO_HASH_TYPE_NONE,
	PHP_CRYPTO_HASH_TYPE_MD,
	PHP_CRYPTO_HASH_TYPE_HMAC,
	PHP_CRYPTO_HASH_TYPE_CMAC
} php_crypto_hash_type;

typedef enum {
	PHP_CRYPTO_HASH_STATUS_CLEAR,
	PHP_CRYPTO_HASH_STATUS_HASH
} php_crypto_hash_status;

PHPC_OBJ_STRUCT_BEGIN(crypto_hash)
	php_crypto_hash_type type;
	php_crypto_hash_status status;
	union {
		const EVP_MD *md;
#ifdef PHP_CRYPTO_HAS_CMAC
		const EVP_CIPHER *cipher;
#endif
	} alg;
	union {
		EVP_MD_CTX *md;
		HMAC_CTX *hmac;
#ifdef PHP_CRYPTO_HAS_CMAC
		CMAC_CTX *cmac;
#endif
	} ctx;
	char *key;
	int key_len;
PHPC_OBJ_STRUCT_END()

/* Hash or MAC object accessors */
#ifdef PHP_CRYPTO_HAS_CMAC
#define PHP_CRYPTO_CMAC_CTX(pobj) (pobj)->ctx.cmac
#define PHP_CRYPTO_CMAC_ALG(pobj) (pobj)->alg.cipher
#endif
#define PHP_CRYPTO_HASH_CTX(pobj) (pobj)->ctx.md
#define PHP_CRYPTO_HASH_ALG(pobj) (pobj)->alg.md
#define PHP_CRYPTO_HMAC_CTX(pobj) (pobj)->ctx.hmac
#define PHP_CRYPTO_HMAC_ALG(pobj) (pobj)->alg.md

/* Exceptions */
PHP_CRYPTO_EXCEPTION_EXPORT(Hash)
PHP_CRYPTO_EXCEPTION_EXPORT(MAC)
/* Error infos */
PHP_CRYPTO_ERROR_INFO_EXPORT(MAC)


/* CLASSES */

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hash_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_hmac_ce;
#ifdef PHP_CRYPTO_HAS_CMAC
extern PHP_CRYPTO_API zend_class_entry *php_crypto_cmac_ce;
#endif

/* USER METHODS */

/* Module init for Crypto Hash */
PHP_MINIT_FUNCTION(crypto_hash);

/* Hash methods */
PHP_CRYPTO_METHOD(Hash, getAlgorithms);
PHP_CRYPTO_METHOD(Hash, hasAlgorithm);
PHP_CRYPTO_METHOD(Hash, __callStatic);
PHP_CRYPTO_METHOD(Hash, __construct);
PHP_CRYPTO_METHOD(Hash, getAlgorithmName);
PHP_CRYPTO_METHOD(Hash, update);
PHP_CRYPTO_METHOD(Hash, digest);
PHP_CRYPTO_METHOD(Hash, hexdigest);
PHP_CRYPTO_METHOD(Hash, getSize);
PHP_CRYPTO_METHOD(Hash, getBlockSize);

/* MAC methods */
PHP_CRYPTO_METHOD(MAC, __construct);


/* CRYPTO API FUNCTIONS */
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
