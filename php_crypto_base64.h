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

typedef struct {
	zend_object zo;
	php_crypto_base64_status status;
	EVP_ENCODE_CTX *ctx;
} php_crypto_base64_object;

/* Base64 macros for endoding and decoding context size */
#define PHP_CRYPTO_BASE64_DECODING_SIZE_MIN 49
#define PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN 65
#define PHP_CRYPTO_BASE64_ENCODING_SIZE_REAL(data_len, b64ctx) (((data_len) + 2) * 4 / 3 + data_len / (b64ctx)->length + 1)
#define PHP_CRYPTO_BASE64_DECODING_SIZE_REAL(data_len) (((data_len) + 2) * 3 / 4)

/* Base64 exceptions macros */
#define PHP_CRYPTO_BASE64_E(code) PHP_CRYPTO_BASE64_ERROR_##code
#define PHP_CRYPTO_THROW_BASE64_EXCEPTION(code, msg) \
	PHP_CRYPTO_THROW_EXCEPTION(php_crypto_base64_exception_ce, PHP_CRYPTO_BASE64_E(code), msg)
#define PHP_CRYPTO_THROW_BASE64_EXCEPTION_EX(code, msg, ...) \
	PHP_CRYPTO_THROW_EXCEPTION_EX(php_crypto_base64_exception_ce, PHP_CRYPTO_BASE64_E(code), msg, ##__VA_ARGS__)

/* Base64 exception error codes */
typedef enum {
	PHP_CRYPTO_BASE64_E(ENCODE_UPDATE_STATUS) = 1,
	PHP_CRYPTO_BASE64_E(ENCODE_FINISH_STATUS),
	PHP_CRYPTO_BASE64_E(DECODE_UPDATE_STATUS),
	PHP_CRYPTO_BASE64_E(DECODE_FINISH_STATUS),
	PHP_CRYPTO_BASE64_E(DECODE_FAILED)
} php_crypto_base64_error_code;


/* Class entries */
extern PHP_CRYPTO_API zend_class_entry *php_crypto_base64_ce;
extern PHP_CRYPTO_API zend_class_entry *php_crypto_base64_exception_ce;

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
