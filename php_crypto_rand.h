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

#ifndef PHP_CRYPTO_RAND_H
#define PHP_CRYPTO_RAND_H

#include "php.h"
#include "php_crypto.h"

#include <openssl/rand.h>

/* Rand exceptions macros */
#define PHP_CRYPTO_RAND_E(code) PHP_CRYPTO_RAND_ERROR_##code
#define PHP_CRYPTO_THROW_RAND_EXCEPTION(code, msg) \
	PHP_CRYPTO_THROW_EXCEPTION(php_crypto_rand_exception_ce, PHP_CRYPTO_RAND_E(code), msg)
#define PHP_CRYPTO_THROW_RAND_EXCEPTION_EX(code, msg, ...) \
	PHP_CRYPTO_THROW_EXCEPTION_EX(php_crypto_rand_exception_ce, PHP_CRYPTO_RAND_E(code), msg, ##__VA_ARGS__)

/* Rand exception error codes */
typedef enum {
	PHP_CRYPTO_RAND_E(GENERATE_PREDICTABLE) = 1,
	PHP_CRYPTO_RAND_E(FILE_WRITE_PREDICTABLE)
} php_crypto_rand_error_code;

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_rand_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_rand_exception_ce;

/* Methods definitions */
PHP_MINIT_FUNCTION(crypto_rand);
PHP_CRYPTO_METHOD(Rand, generate);
PHP_CRYPTO_METHOD(Rand, seed);
PHP_CRYPTO_METHOD(Rand, cleanup);
PHP_CRYPTO_METHOD(Rand, loadFile);
PHP_CRYPTO_METHOD(Rand, writeFile);
PHP_CRYPTO_METHOD(Rand, egd);

#endif	/* PHP_CRYPTO_RAND_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
