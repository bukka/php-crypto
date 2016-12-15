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
	KEY_LENGTH_LOW,
	"The key lenght is too low"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	KEY_LENGTH_HIGH,
	"The key lenght is too high"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	SALT_LENGTH_HIGH,
	"The salt is too long"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	PASSWORD_LENGTH_INVALID,
	"The password is too long"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DERIVATION_FAILED,
	"KDF derivation failed"
)
PHP_CRYPTO_ERROR_INFO_END()

PHP_CRYPTO_EXCEPTION_DEFINE(PBKDF2)
PHP_CRYPTO_ERROR_INFO_BEGIN(PBKDF2)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	HASH_ALGORITHM_NOT_FOUND,
	"Hash algorithm '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	ITERATIONS_HIGH,
	"Iterations count is too high"
)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_kdf_new, 0, 0, 1)
ZEND_ARG_INFO(0, length)
ZEND_ARG_INFO(0, salt)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_kdf_derive, 0)
ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_kdf_length, 0)
ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_kdf_salt, 0)
ZEND_ARG_INFO(0, salt)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_kdf_object_methods[] = {
	PHP_CRYPTO_ME(
		KDF, __construct,
		arginfo_crypto_kdf_new,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ABSTRACT_ME(
		KDF, derive,
		arginfo_crypto_kdf_derive
	)
	PHP_CRYPTO_ME(
		KDF, getLength,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		KDF, setLength,
		arginfo_crypto_kdf_length,
		ZEND_ACC_PUBLIC
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_pbkdf2_new, 0, 0, 2)
ZEND_ARG_INFO(0, hashAlgorithm)
ZEND_ARG_INFO(0, length)
ZEND_ARG_INFO(0, salt)
ZEND_ARG_INFO(0, iterations)
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
		arginfo_crypto_pbkdf2_new,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		PBKDF2, derive,
		arginfo_crypto_kdf_derive,
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

	PHPC_THIS->key_len = 0;
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
	PHPC_THAT->key_len = PHPC_THIS->key_len;
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
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(PBKDF2), php_crypto_pbkdf2_object_methods);
	php_crypto_pbkdf2_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_kdf_ce, NULL);

	/* PBKDF2 Exception registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, PBKDF2, KDF);
	PHP_CRYPTO_ERROR_INFO_REGISTER(PBKDF2);
#endif

	return SUCCESS;
}
/* }}} */

/* KDF methods */

/* {{{ php_crypto_kdf_set_key_len */
static int php_crypto_kdf_set_key_len(PHPC_THIS_DECLARE(crypto_kdf),
		phpc_long_t key_len TSRMLS_DC)
{
	int key_len_int;

	if (key_len <= 0) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(KDF, KEY_LENGTH_LOW));
		return FAILURE;
	}
	if (php_crypto_long_to_int(key_len, &key_len_int) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(KDF, KEY_LENGTH_HIGH));
		return FAILURE;
	}

	PHPC_THIS->key_len = key_len_int;

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_kdf_set_salt */
static int php_crypto_kdf_set_salt(PHPC_THIS_DECLARE(crypto_kdf),
		char *salt, phpc_str_size_t salt_len TSRMLS_DC)
{
	int salt_len_int;

	if (php_crypto_str_size_to_int(salt_len, &salt_len_int) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(KDF, SALT_LENGTH_HIGH));
		return FAILURE;
	}

	if (PHPC_THIS->salt == NULL) {
		PHPC_THIS->salt = emalloc(salt_len + 1);
	} else if (PHPC_THIS->salt_len != salt_len) {
		PHPC_THIS->salt = erealloc(PHPC_THIS->salt, salt_len + 1);
	}

	memcpy(PHPC_THIS->salt, salt, salt_len);
	PHPC_THIS->salt[salt_len] = '\0';
	PHPC_THIS->salt_len = salt_len_int;

	return SUCCESS;
}
/* }}} */


/* {{{ proto Crypto\KDF::__construct(int $length, string $salt = NULL)
	KDF constructor */
PHP_CRYPTO_METHOD(KDF, __construct)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	char *salt = NULL;
	phpc_str_size_t salt_len;
	phpc_long_t key_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s",
			&key_len, &salt, &salt_len) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	php_crypto_kdf_set_key_len(PHPC_THIS, key_len TSRMLS_CC);
	if (salt != NULL) {
		php_crypto_kdf_set_salt(PHPC_THIS, salt, salt_len TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto int Crypto\KDF::getLength()
	Get key length */
PHP_CRYPTO_METHOD(KDF, getLength)
{
	PHPC_THIS_DECLARE(crypto_kdf);

	if (zend_parse_parameters_none()) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_LONG(PHPC_THIS->key_len);
}
/* }}} */

/* {{{ proto bool Crypto\KDF::setLength(int $length)
	Set key length */
PHP_CRYPTO_METHOD(KDF, setLength)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	phpc_long_t key_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
			&key_len) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_BOOL(php_crypto_kdf_set_key_len(PHPC_THIS, key_len TSRMLS_CC) == SUCCESS);
}
/* }}} */

/* {{{ proto string Crypto\KDF::getSalt()
	Get salt */
PHP_CRYPTO_METHOD(KDF, getSalt)
{
	PHPC_THIS_DECLARE(crypto_kdf);

	if (zend_parse_parameters_none()) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	if (PHPC_THIS->salt == NULL) {
		RETURN_NULL();
	}

	PHPC_CSTRL_RETURN(PHPC_THIS->salt, PHPC_THIS->salt_len);
}
/* }}} */

/* {{{ proto bool Crypto\KDF::setSalt(string $salt)
	Set salt */
PHP_CRYPTO_METHOD(KDF, setSalt)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	char *salt = NULL;
	phpc_str_size_t salt_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&salt, &salt_len) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_BOOL(php_crypto_kdf_set_salt(PHPC_THIS, salt, salt_len TSRMLS_CC) == SUCCESS);
}
/* }}} */

#ifdef PHP_CRYPTO_HAS_PBKDF2
/* PBKDF2 methods */

/* {{{ php_crypto_pbkdf2_set_hash_algorithm */
static int php_crypto_pbkdf2_set_hash_algorithm(PHPC_THIS_DECLARE(crypto_kdf),
		char *hash_alg TSRMLS_DC)
{
	const EVP_MD *digest = EVP_get_digestbyname(hash_alg);

	if (!digest) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(PBKDF2, HASH_ALGORITHM_NOT_FOUND), hash_alg);
		return FAILURE;
	}
	PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THIS) = digest;

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_pbkdf2_set_iterations */
static int php_crypto_pbkdf2_set_iterations(PHPC_THIS_DECLARE(crypto_kdf),
		 phpc_long_t iterations TSRMLS_DC)
{
	int iterations_int;

	if (php_crypto_long_to_int(iterations, &iterations_int) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(PBKDF2, ITERATIONS_HIGH));
		return FAILURE;
	}
	PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THIS) = iterations_int;

	return SUCCESS;
}
/* }}} */

/* {{{ proto Crypto\PBKDF2::__construct(string $hashAlgorithm, int $length,
			string $salt = NULL, int $iterations = 1000)
	KDF constructor */
PHP_CRYPTO_METHOD(PBKDF2, __construct)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	char *hash_alg, *salt = NULL;
	phpc_str_size_t hash_alg_len, salt_len;
	phpc_long_t key_len, iterations = PHP_CRYPTO_PBKDF2_ITER_DEFAULT;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|sl",
			&hash_alg, &hash_alg_len, &key_len, &salt, &salt_len, &iterations) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	php_crypto_pbkdf2_set_hash_algorithm(PHPC_THIS, hash_alg TSRMLS_CC);
	php_crypto_kdf_set_key_len(PHPC_THIS, key_len TSRMLS_CC);
	if (salt != NULL) {
		php_crypto_kdf_set_salt(PHPC_THIS, salt, salt_len TSRMLS_CC);
	}
	php_crypto_pbkdf2_set_iterations(PHPC_THIS, iterations TSRMLS_CC);
}
/* }}} */

/* {{{ proto string Crypto\PBKDF2::derive(string $password)
	Deriver hash for password */
PHP_CRYPTO_METHOD(PBKDF2, derive)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	PHPC_STR_DECLARE(key);
	char *password;
	phpc_str_size_t password_len;
	int password_len_int, hash_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&password, &password_len) == FAILURE) {
		return;
	}

	if (php_crypto_str_size_to_int(password_len, &password_len_int) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(KDF, PASSWORD_LENGTH_INVALID));
		RETURN_NULL();
	}
	PHPC_THIS_FETCH(crypto_kdf);
	PHPC_STR_ALLOC(key, PHPC_THIS->key_len);

	if (!PKCS5_PBKDF2_HMAC(password, password_len_int, PHPC_THIS->salt, PHPC_THIS->salt_len,
			PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THIS), PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THIS),
			PHPC_THIS->key_len, PHPC_STR_VAL(key))) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(KDF, DERIVATION_FAILED));
		RETURN_NULL();
	}
	PHPC_STR_VAL(key)[PHPC_THIS->key_len] = '\0';

	PHPC_STR_RETURN(key);
}
/* }}} */

/* {{{ proto int Crypto\PBKDF2::getIterations()
	Get iterations */
PHP_CRYPTO_METHOD(PBKDF2, getIterations)
{
	PHPC_THIS_DECLARE(crypto_kdf);

	if (zend_parse_parameters_none()) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_LONG(PHP_CRYPTO_PBKDF2_CTX_ITER(PHPC_THIS));
}
/* }}} */

/* {{{ proto bool Crypto\PBKDF2::setIterations(int $iterations)
	Set iterations */
PHP_CRYPTO_METHOD(PBKDF2, setIterations)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	phpc_long_t iterations;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
			&iterations) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_BOOL(php_crypto_pbkdf2_set_iterations(PHPC_THIS, iterations TSRMLS_CC) == SUCCESS);
}
/* }}} */

/* {{{ proto string Crypto\PBKDF2::getHashAlgorithm()
	Get hash algorithm */
PHP_CRYPTO_METHOD(PBKDF2, getHashAlgorithm)
{
	const EVP_MD *md;
	PHPC_THIS_DECLARE(crypto_kdf);

	if (zend_parse_parameters_none()) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	md = PHP_CRYPTO_PBKDF2_CTX_MD(PHPC_THIS);
	if (md == NULL) {
		RETURN_NULL();
	}

	PHPC_CSTR_RETURN(EVP_MD_name(md));
}
/* }}} */

/* {{{ proto bool Crypto\PBKDF2::setHashAlgorithm(string $hashAlgorithm)
	Set hash algorithm */
PHP_CRYPTO_METHOD(PBKDF2, setHashAlgorithm)
{
	PHPC_THIS_DECLARE(crypto_kdf);
	char *hash_alg;
	phpc_str_size_t hash_alg_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&hash_alg, &hash_alg_len) == FAILURE) {
		return;
	}
	PHPC_THIS_FETCH(crypto_kdf);

	RETURN_BOOL(php_crypto_pbkdf2_set_hash_algorithm(PHPC_THIS, hash_alg TSRMLS_CC) == SUCCESS);
}
/* }}} */
#endif
