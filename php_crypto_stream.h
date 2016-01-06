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

#ifndef PHP_CRYPTO_STREAM_H
#define	PHP_CRYPTO_STREAM_H

#include "php_crypto.h"

#define PHP_CRYPTO_STREAM_SCHEME_PREFIX "://"

/* general wrapper name for selecting context options s*/
#define PHP_CRYPTO_STREAM_WRAPPER_NAME "crypto"

/* file stream */
#define PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME "crypto.file"
#define PHP_CRYPTO_STREAM_FILE_SCHEME \
	PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME PHP_CRYPTO_STREAM_SCHEME_PREFIX
#define PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE sizeof(PHP_CRYPTO_STREAM_FILE_SCHEME) - 1

/* stream meta headers for cipher authentication */
#define PHP_CRYPTO_STREAM_META_AUTH_TAG    "X-PHP-Crypto-Auth-Tag"
#define PHP_CRYPTO_STREAM_META_AUTH_RESULT "X-PHP-Crypto-Auth-Result"

/* Error info */
PHP_CRYPTO_ERROR_INFO_EXPORT(Stream)
		
/* Stream error action */
#define PHP_CRYPTO_STREAM_ERROR_ACTION PHP_CRYPTO_ERROR_ACTION_ERROR

/* Stream error args macro */
#define PHP_CRYPTO_STREAM_ERROR_ARGS(einame) \
	PHP_CRYPTO_ERROR_ARGS_EX(Stream, NULL, PHP_CRYPTO_STREAM_ERROR_ACTION, einame)

/* Module init and shut down callbacks */
PHP_MINIT_FUNCTION(crypto_stream);
PHP_MSHUTDOWN_FUNCTION(crypto_stream);

#endif	/* PHP_CRYPTO_STREAM_H */

