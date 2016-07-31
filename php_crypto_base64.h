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

#ifndef PHP_CRYPTO_BASE64_H
#define PHP_CRYPTO_BASE64_H

#include "php.h"
#include "php_crypto.h"

#include <openssl/evp.h>

typedef enum {
	PHP_CRYPTO_BASE64_STATUS_CLEAR,
	PHP_CRYPTO_BASE64_STATUS_ENCODE,
	PHP_CRYPTO_BASE64_STATUS_DECODE
} php_crypto_base64_status;

PHPC_OBJ_STRUCT_BEGIN(crypto_base64)
	php_crypto_base64_status status;
	EVP_ENCODE_CTX *ctx;
PHPC_OBJ_STRUCT_END()

/* Base64 macros for endoding and decoding context size */
#define PHP_CRYPTO_BASE64_DECODING_SIZE_MIN 50
#define PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN 66

/* Exceptions */
PHP_CRYPTO_EXCEPTION_EXPORT(Base64)
/* Error info */
PHP_CRYPTO_ERROR_INFO_EXPORT(Base64)

/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_base64_ce;

/* Module init for Crypto Base64 */
PHP_MINIT_FUNCTION(crypto_base64);

/* Base64 methods */
PHP_CRYPTO_METHOD(Base64, encode);
PHP_CRYPTO_METHOD(Base64, decode);
PHP_CRYPTO_METHOD(Base64, __construct);
PHP_CRYPTO_METHOD(Base64, encodeUpdate);
PHP_CRYPTO_METHOD(Base64, encodeFinish);
PHP_CRYPTO_METHOD(Base64, decodeUpdate);
PHP_CRYPTO_METHOD(Base64, decodeFinish);

#endif	/* PHP_CRYPTO_BASE64_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
