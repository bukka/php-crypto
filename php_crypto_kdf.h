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

#ifndef PHP_CRYPTO_KDF_H
#define PHP_CRYPTO_KDF_H

#include "php.h"
#include "php_crypto.h"

/* PBKDF2 feature test */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define PHP_CRYPTO_HAS_PBKDF2 1
#endif

typedef enum {
	PHP_CRYPTO_KDF_TYPE_NONE,
	PHP_CRYPTO_KDF_TYPE_PBKDF2
} php_crypto_kdf_type;

PHPC_OBJ_STRUCT_BEGIN(crypto_kdf)
	php_crypto_kdf_type type;
	union {
		struct {
			const EVP_MD *md;
			int iter;
		} pbkdf2;
	} ctx;
	char *salt;
	int salt_len;
	int key_len;
PHPC_OBJ_STRUCT_END()


#define PHP_CRYPTO_PBKDF2_CTX_MD(pobj) (pobj)->ctx.pbkdf2.md
#define PHP_CRYPTO_PBKDF2_CTX_ITER(pobj) (pobj)->ctx.pbkdf2.iter

#define PHP_CRYPTO_PBKDF2_ITER_DEFAULT 1000

/* Exceptions */
PHP_CRYPTO_EXCEPTION_EXPORT(KDF)
PHP_CRYPTO_EXCEPTION_EXPORT(PBKDF2)

/* CLASSES */

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_kdf_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_pbkdf2_ce;

/* USER METHODS */

/* Module init for Crypto KDF */
PHP_MINIT_FUNCTION(crypto_kdf);

/* KDF methods */
PHP_CRYPTO_METHOD(KDF, __construct);
PHP_CRYPTO_METHOD(KDF, getLength);
PHP_CRYPTO_METHOD(KDF, setLength);
PHP_CRYPTO_METHOD(KDF, getSalt);
PHP_CRYPTO_METHOD(KDF, setSalt);

#ifdef PHP_CRYPTO_HAS_PBKDF2
/* PBKDF2 methods */
PHP_CRYPTO_METHOD(PBKDF2, __construct);
PHP_CRYPTO_METHOD(PBKDF2, derive);
PHP_CRYPTO_METHOD(PBKDF2, getIterations);
PHP_CRYPTO_METHOD(PBKDF2, setIterations);
PHP_CRYPTO_METHOD(PBKDF2, getHashAlgorithm);
PHP_CRYPTO_METHOD(PBKDF2, setHashAlgorithm);
#endif

#endif	/* PHP_CRYPTO_KDF_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
