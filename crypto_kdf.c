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

#ifdef PHP_CRYPTO_HAS_PBKDF2

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

PHP_CRYPTO_API zend_class_entry *php_crypto_kdf_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_pbkdf2_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_kdf);

/* {{{ crypto_kdf free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_kdf)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_kdf);

	if (PHPC_THIS->salt) {
		efree(PHPC_THIS->salt);
	}

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_kdf create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_kdf)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_kdf);

	if (PHPC_CLASS_TYPE == php_crypto_pbkdf2_ce) {
		PHPC_THIS->type = PHP_CRYPTO_KDF_TYPE_PBKDF2;
		PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THIS) = NULL;
		PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THIS) = PHP_CRYPTO_PBKDF2_ITER_DEFAULT;
	}
	else {
		PHPC_THIS->type = PHP_CRYPTO_KDF_TYPE_NONE;
	}

	PHPC_THIS->salt = NULL;
	PHPC_THIS->salt_len = 0;

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(crypto_kdf);
}
/* }}} */

/* {{{ crypto_kdf create object handler */
PHPC_OBJ_HANDLER_CREATE(crypto_kdf)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(crypto_kdf);
}
/* }}} */

/* {{{ crypto_kdf clone object handler */
PHPC_OBJ_HANDLER_CLONE(crypto_kdf)
{
	zend_bool copy_success;
	PHPC_OBJ_HANDLER_CLONE_INIT(crypto_kdf);

	PHPC_THAT->type = PHPC_THIS->type;
	if (PHPC_THIS->salt) {
		PHPC_THAT->salt = emalloc(PHPC_THIS->salt_len + 1);
		memcpy(PHPC_THAT->salt, PHPC_THIS->salt, PHPC_THIS->salt_len + 1);
		PHPC_THAT->salt_len = PHPC_THIS->salt_len;
	}

	if (PHPC_THAT->type == PHP_CRYPTO_KDF_TYPE_PBKDF2) {
		PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THAT) = PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THIS);
		PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THAT) = PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THIS);
	}

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_kdf)
{
	zend_class_entry ce;

	/* Hash class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(KDF), php_crypto_kdf_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, crypto_kdf);
	php_crypto_kdf_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(crypto_kdf);
	PHPC_OBJ_SET_HANDLER_OFFSET(crypto_kdf);
	PHPC_OBJ_SET_HANDLER_FREE(crypto_kdf);
	PHPC_OBJ_SET_HANDLER_CLONE(crypto_kdf);
	php_crypto_kdf_ce->ce_flags |= ZEND_ACC_EXPLICIT_ABSTRACT_CLASS;

	/* HashException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, KDF);
	PHP_CRYPTO_ERROR_INFO_REGISTER(KDF);

#ifdef PHP_CRYPTO_HAS_PBKDF2
	/* PBKDF2 class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(PBKDF2), NULL);
	php_crypto_pbkdf2_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_kdf_ce, NULL);

	/* PBKDF2 Exception registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, PBKDF2, KDF);
#endif

	return SUCCESS;
}
/* }}} */

/* KDF methods */

/* {{{ proto Crypto\KDF::__construct()
	KDF constructor */
PHP_CRYPTO_METHOD(KDF, __construct)
{

}
/* }}} */

/* {{{ proto string Crypto\KDF::getSalt()
	Get salt */
PHP_CRYPTO_METHOD(KDF, getSalt)
{

}
/* }}} */

/* {{{ proto void Crypto\KDF::setSalt(string $salt)
	Get salt */
PHP_CRYPTO_METHOD(KDF, setSalt)
{

}
/* }}} */

/* PBKDF2 methods */

/* {{{ proto Crypto\PBKDF2::__construct()
	KDF constructor */
PHP_CRYPTO_METHOD(PBKDF2, __construct)
{

}
/* }}} */

/* {{{ proto Crypto\PBKDF2::deriver(string $password)
	Deriver hash for password */
PHP_CRYPTO_METHOD(PBKDF2, derive)
{

}
/* }}} */

/* {{{ proto int Crypto\PBKDF2::getIterations()
	Get iterations */
PHP_CRYPTO_METHOD(PBKDF2, getIterations)
{

}
/* }}} */

/* {{{ proto void Crypto\PBKDF2::setIterations(int $iterations)
	Set iterations */
PHP_CRYPTO_METHOD(PBKDF2, setIterations)
{

}
/* }}} */

/* {{{ proto string Crypto\PBKDF2::getHashAlgorithm()
	Get hash algorithm */
PHP_CRYPTO_METHOD(PBKDF2, getHashAlgorithm)
{

}
/* }}} */

/* {{{ proto void Crypto\PBKDF2::setHashAlgorithm(string $hashAlgorithm)
	Set hash algorithm */
PHP_CRYPTO_METHOD(PBKDF2, setHashAlgorithm)
{

}
/* }}} */

