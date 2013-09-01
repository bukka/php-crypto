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

#include "php.h"
#include "php_crypto.h"
#include "php_crypto_rand.h"
#include "zend_exceptions.h"

#include <openssl/rand.h>
#include <openssl/err.h>

ZEND_BEGIN_ARG_INFO(arginfo_crypto_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_generate, 0, 0, 1)
ZEND_ARG_INFO(0, num)
ZEND_ARG_INFO(0, strong)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_rand_seed, 0, 0, 1)
ZEND_ARG_INFO(0, buf)
ZEND_ARG_INFO(0, entropy)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_rand_object_methods[] = {
	PHP_CRYPTO_ME(Rand,   generate,     arginfo_crypto_rand_generate,     ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   seed,         arginfo_crypto_rand_seed,         ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Rand,   cleanup,      NULL,                             ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_rand_ce;

/* exception entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_rand_exception_ce;

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_rand)
{
	zend_class_entry ce;

	/* Rand class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Rand), php_crypto_rand_object_methods);
	php_crypto_rand_ce = zend_register_internal_class(&ce TSRMLS_CC);
	
	/* Algorithm Exception class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(RandException), NULL);
	php_crypto_rand_exception_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ proto string Rand::generate(int $num, bool $strong = true)
   Generate pseudo random bytes */
PHP_CRYPTO_METHOD(Rand, generate)
{
	long num, strong = 1;
	char *buf;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &num, &strong) == FAILURE) {
		return;
	}

	buf = emalloc(sizeof(buf) * num + 1);
	if (strong) {
		if (!RAND_bytes((unsigned char *) buf, num)) {
			PHP_CRYPTO_THROW_RAND_EXCEPTION(0, "The PRNG state is not yet unpridactable");
		}
	} else {
		RAND_pseudo_bytes((unsigned char *) buf, num);
	}
	buf[num] = '\0';
	RETURN_STRING(buf, 0);
}
/* }}} */

/* {{{ proto void Rand::seed(string $buf, float $entropy = (float) strlen($buf))
   Seed PRNG */
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

/* {{{ proto void Rand::cleanup()
   Clean up PRNG */
PHP_CRYPTO_METHOD(Rand, cleanup)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RAND_cleanup();
}
/* }}} */
