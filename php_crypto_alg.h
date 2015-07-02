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
			const EVP_MD *alg;
			union {
				EVP_MD_CTX *md;
				HMAC_CTX *hmac;
			} ctx;
		} hash;
	} evp;
PHPC_OBJ_STRUCT_END()
/* php_crypto_algorithm_object -> struct _phpc_crypto_alg__obj */

/* Algorithm object accessors */
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
PHP_CRYPTO_EXCEPTION_EXPORT(Hash)
/* Error infos */
PHP_CRYPTO_ERROR_INFO_EXPORT(Hash)




/* CLASSES */

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
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
