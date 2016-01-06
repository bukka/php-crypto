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
#include "php_crypto_rand.h"
#include "zend_exceptions.h"

#include <openssl/rand.h>
#include <openssl/err.h>

PHP_CRYPTO_EXCEPTION_DEFINE(Rand)
PHP_CRYPTO_ERROR_INFO_BEGIN(Rand)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	GENERATE_PREDICTABLE,
	"The PRNG state is not yet unpredictable"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILE_WRITE_PREDICTABLE,
	"The bytes written were generated without appropriate seed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	REQUESTED_BYTES_NUMBER_TOO_HIGH,
	"The requested number of bytes is too high"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	SEED_LENGTH_TOO_HIGH,
	"The supplied seed length is too high"
)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_generate, 0, 0, 1)
ZEND_ARG_INFO(0, num)
ZEND_ARG_INFO(0, must_be_strong)
ZEND_ARG_INFO(1, returned_strong_result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_seed, 0, 0, 1)
ZEND_ARG_INFO(0, buf)
ZEND_ARG_INFO(0, entropy)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_load_file, 0, 0, 1)
ZEND_ARG_INFO(0, filename)
ZEND_ARG_INFO(0, max_bytes)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_rand_write_file, 0)
ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_rand_object_methods[] = {
	PHP_CRYPTO_ME(
		Rand, generate,
		arginfo_crypto_rand_generate,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Rand, seed,
		arginfo_crypto_rand_seed,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Rand, cleanup,
		NULL,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Rand, loadFile,
		arginfo_crypto_rand_load_file,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Rand, writeFile,
		arginfo_crypto_rand_write_file,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_rand_ce;

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_rand)
{
	zend_class_entry ce;

	/* Rand class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Rand),
			php_crypto_rand_object_methods);
	php_crypto_rand_ce = PHPC_CLASS_REGISTER(ce);

	/* RandException class */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, Rand);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Rand);

	return SUCCESS;
}
/* }}} */

/* {{{ proto static string Crypto\Rand::generate(
			int $num, bool $must_be_strong = true,
			&bool $returned_strong_result = true)
	Generates pseudo random bytes */
PHP_CRYPTO_METHOD(Rand, generate)
{
	phpc_long_t num_long;
	int num;
	PHPC_STR_DECLARE(buf);
	zval *zstrong_result = NULL;
	zend_bool strong_result, must_be_strong = 1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|bz/",
				&num_long, &must_be_strong, &zstrong_result) == FAILURE) {
		return;
	}

	if (php_crypto_long_to_int(num_long, &num) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Rand, REQUESTED_BYTES_NUMBER_TOO_HIGH));
		RETURN_FALSE;
	}


	PHPC_STR_ALLOC(buf, num);

	if (must_be_strong) {
		if (!RAND_bytes((unsigned char *) PHPC_STR_VAL(buf), num)) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Rand, GENERATE_PREDICTABLE));
			PHPC_STR_RELEASE(buf);
			RETURN_FALSE;
		}
		strong_result = 1;
	} else {
		strong_result = RAND_pseudo_bytes((unsigned char *) PHPC_STR_VAL(buf), num);
	}
	if (zstrong_result) {
		ZVAL_BOOL(zstrong_result, strong_result);
	}
	PHPC_STR_VAL(buf)[num] = '\0';
	PHPC_STR_RETURN(buf);
}
/* }}} */

/* {{{ proto static void Crypto\Rand::seed(
			string $buf, float $entropy = (float) strlen($buf))
	Mixes bytes in $buf into PRNG state */
PHP_CRYPTO_METHOD(Rand, seed)
{
	char *buf;
	phpc_str_size_t buf_str_size;
	int buf_len;
	double entropy;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|d",
				&buf, &buf_str_size, &entropy) == FAILURE) {
		return;
	}

	if (php_crypto_str_size_to_int(buf_str_size, &buf_len) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Rand, SEED_LENGTH_TOO_HIGH));
		RETURN_NULL();
	}

	if (ZEND_NUM_ARGS() == 1) {
		entropy = (double) buf_len;
	}

	RAND_add(buf, buf_len, entropy);
}
/* }}} */

/* {{{ proto static void Crypto\Rand::cleanup()
   Cleans up PRNG state */
PHP_CRYPTO_METHOD(Rand, cleanup)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RAND_cleanup();
	RETURN_NULL();
}
/* }}} */

/* {{{ proto static int Crypto\Rand::loadFile(string $filename, int $max_bytes = -1)
	Reads a number of bytes from file $filename and adds them
	to the PRNG. If max_bytes is non-negative, up to to max_bytes
	are read; if $max_bytes is negative, the complete file is read */
PHP_CRYPTO_METHOD(Rand, loadFile)
{
	char *path;
	phpc_str_size_t path_len;
	phpc_long_t max_bytes_len = -1;
	int max_bytes;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, PHPC_PATH_ZPP_FLAG"|l",
			&path, &path_len, &max_bytes_len) == FAILURE) {
		return;
	}

	if (php_crypto_long_to_int(max_bytes_len, &max_bytes) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Rand, REQUESTED_BYTES_NUMBER_TOO_HIGH));
		RETURN_FALSE;
	}

	if (max_bytes < -1) {
		max_bytes = -1;
	}

	RETURN_LONG(RAND_load_file(path, max_bytes));
}
/* }}} */


/* {{{ proto static int Crypto\Rand::writeFile(string $filename)
	Writes a number of random bytes (currently 1024) to file $filename
	which can be used to initializethe PRNG by calling
	Crypto\Rand::loadFile() in a later session */
PHP_CRYPTO_METHOD(Rand, writeFile)
{
	char *path;
	phpc_str_size_t path_len;
	int bytes_written;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, PHPC_PATH_ZPP_FLAG,
			&path, &path_len) == FAILURE) {
		return;
	}

	bytes_written = RAND_write_file(path);
	if (bytes_written < 0) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Rand, FILE_WRITE_PREDICTABLE));
		RETURN_FALSE;
	} else {
		RETURN_LONG((phpc_long_t) bytes_written);
	}
}
/* }}} */
