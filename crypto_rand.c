/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 Jakub Zelenka                                |
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_egd, 0, 0, 1)
ZEND_ARG_INFO(0, path)
ZEND_ARG_INFO(0, bytes)
ZEND_ARG_INFO(0, seed)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_rand_object_methods[] = {
	PHP_CRYPTO_ME(Rand,   generate,     arginfo_crypto_rand_generate,     ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   seed,         arginfo_crypto_rand_seed,         ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   cleanup,      NULL,                             ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   loadFile,     arginfo_crypto_rand_load_file,    ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   writeFile,    arginfo_crypto_rand_write_file,   ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   egd,          arginfo_crypto_rand_egd,          ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_FE_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_rand_ce;

/* exception entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_rand_exception_ce;

#define PHP_CRYPTO_DECLARE_RAND_E_CONST(rconst) \
	zend_declare_class_constant_long(php_crypto_rand_exception_ce, #rconst, sizeof(#rconst)-1, PHP_CRYPTO_RAND_E(rconst) TSRMLS_CC)

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_rand)
{
	zend_class_entry ce;

	/* Rand class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Rand), php_crypto_rand_object_methods);
	php_crypto_rand_ce = zend_register_internal_class(&ce TSRMLS_CC);

	/* Rand Exception class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(RandException), NULL);
	php_crypto_rand_exception_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	/* Declare RandException class constants for error codes */
	PHP_CRYPTO_DECLARE_RAND_E_CONST(GENERATE_PREDICTABLE);
	PHP_CRYPTO_DECLARE_RAND_E_CONST(FILE_WRITE_PREDICTABLE);

	return SUCCESS;
}
/* }}} */

/* {{{ proto static string Crypto\Rand::generate(int $num, bool $must_be_strong = true, &bool $returned_strong_result = true)
   Generates pseudo random bytes */
PHP_CRYPTO_METHOD(Rand, generate)
{
	long num;
	char *buf;
	zval *zstrong_result = NULL;
	zend_bool strong_result, must_be_strong = 1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|bz", &num, &must_be_strong, &zstrong_result) == FAILURE) {
		return;
	}

	buf = emalloc(sizeof(buf) * num + 1);

	if (must_be_strong) {
		if (!RAND_bytes((unsigned char *) buf, num)) {
			PHP_CRYPTO_THROW_RAND_EXCEPTION(GENERATE_PREDICTABLE, "The PRNG state is not yet unpridactable");
			efree(buf);
			return;
		}
		strong_result = 1;
	} else {
		strong_result = RAND_pseudo_bytes((unsigned char *) buf, num);
	}
	if (zstrong_result) {
		ZVAL_BOOL(zstrong_result, strong_result);
	}
	buf[num] = '\0';
	RETURN_STRINGL(buf, num, 0);
}
/* }}} */

/* {{{ proto static void Crypto\Rand::seed(string $buf, float $entropy = (float) strlen($buf))
   Mixes bytes in $buf into PRNG state */
PHP_CRYPTO_METHOD(Rand, seed)
{
	char *buf;
	long buf_len;
	double entropy;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|d", &buf, &buf_len, &entropy) == FAILURE) {
		return;
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
}
/* }}} */

/* {{{ proto static int Crypto\Rand::loadFile(string $filename, int $max_bytes = -1)
   Reads a number of bytes from file $filename and adds them to the PRNG. If max_bytes is non-negative,
   up to to max_bytes are read; if $max_bytes is -1, the complete file is read */
PHP_CRYPTO_METHOD(Rand, loadFile)
{
	char *path;
	int path_len;
	long max_bytes = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, PHP_CRYPTO_PATH_FMT"|l", &path, &path_len, &max_bytes) == FAILURE) {
		return;
	}

	RETURN_LONG(RAND_load_file(path, max_bytes));
}
/* }}} */


/* {{{ proto static int Crypto\Rand::writeFile(string $filename)
   Writes a number of random bytes (currently 1024) to file $filename which can be used to initialize
   the PRNG by calling Crypto\Rand::loadFile() in a later session */
PHP_CRYPTO_METHOD(Rand, writeFile)
{
	char *path;
	int path_len, bytes_written;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, PHP_CRYPTO_PATH_FMT, &path, &path_len) == FAILURE) {
		return;
	}

	bytes_written = RAND_write_file(path);
	if (bytes_written < 0) {
		PHP_CRYPTO_THROW_RAND_EXCEPTION(FILE_WRITE_PREDICTABLE, "The bytes written were generated without appropriate seed");
	} else {
		RETURN_LONG(bytes_written);
	}
}
/* }}} */

/* {{{ proto static mixed Crypto\Rand::egd(string $path, int $bytes = 255, bool $seed = true)
   Queries the entropy gathering daemon EGD on socket path. It queries $bytes bytes and if $seed is true,
   then the data are seeded, otherwise the data are returned */
PHP_CRYPTO_METHOD(Rand, egd)
{
	char *path;
	int path_len;
	long bytes = 255;
	zend_bool seed;
	unsigned char *buf = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &path, &path_len, &bytes, &seed) == FAILURE) {
		return;
	}

	if (!seed) {
		buf = emalloc(sizeof(unsigned char) * bytes + 1);
	}

	RAND_query_egd_bytes(path, buf, bytes);

	if (!seed) {
		buf[bytes] = '\0';
		RETVAL_STRINGL((char *) buf, bytes, 0);
	}
}
/* }}} */
