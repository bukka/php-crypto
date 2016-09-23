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


