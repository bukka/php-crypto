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

#ifndef PHP_CRYPTO_STREAM_H
#define	PHP_CRYPTO_STREAM_H

#define PHP_CRYPTO_STREAM_SCHEME_PREFIX "://"

#define PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME "crypto.file"
#define PHP_CRYPTO_STREAM_FILE_SCHEME PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME PHP_CRYPTO_STREAM_SCHEME_PREFIX
#define PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE sizeof(PHP_CRYPTO_STREAM_FILE_SCHEME) - 1

#if PHP_VERSION_ID < 50600
typedef char php_crypto_stream_opener_char_t;
#else
typedef const char php_crypto_stream_opener_char_t;
#endif

PHP_MINIT_FUNCTION(crypto_stream);
PHP_MSHUTDOWN_FUNCTION(crypto_stream);

#endif	/* PHP_CRYPTO_STREAM_H */

