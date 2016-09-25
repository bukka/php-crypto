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

#include "php.h"
#include "php_crypto.h"
#include "zend_exceptions.h"
#include "php_crypto_kdf.h"

#include <openssl/evp.h>

/* PKCS2 feature test */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define PHP_CRYPTO_HAS_PKCS2 1
#endif

PHP_CRYPTO_EXCEPTION_DEFINE(KDF)
PHP_CRYPTO_ERROR_INFO_BEGIN(KDF)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DERIVATION_FAILED,
	"KDF derivation failed"
)
PHP_CRYPTO_ERROR_INFO_END()


ZEND_BEGIN_ARG_INFO(arginfo_crypto_kdf_salt, 0)
ZEND_ARG_INFO(0, salt)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_kdf_object_methods[] = {
	PHP_CRYPTO_ME(
		KDF, __construct,
		arginfo_crypto_kdf_salt,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		KDF, getSalt,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		KDF, setSalt,
		arginfo_crypto_kdf_salt,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

#ifdef PHP_CRYPTO_HAS_PKCS2

ZEND_BEGIN_ARG_INFO(arginfo_crypto_pbkdf2_derive, 0)
ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_pbkdf2_iterations, 0)
ZEND_ARG_INFO(0, iterations)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_pbkdf2_hash_algorithm, 0)
ZEND_ARG_INFO(0, hashAlgorithm)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_pbkdf2_object_methods[] = {
	PHP_CRYPTO_ME(
		PBKDF2, __construct,
		arginfo_crypto_kdf_salt,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, derive,
		arginfo_crypto_pbkdf2_derive,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, getIterations,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, setIterations,
		arginfo_crypto_pbkdf2_iterations,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, getHashAlgorithm,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, setHashAlgorithm,
		arginfo_crypto_pbkdf2_hash_algorithm,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

#endif
