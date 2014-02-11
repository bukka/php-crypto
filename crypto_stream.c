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
#include "php_crypto_stream.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

typedef struct {
	BIO *bio;
} php_crypto_stream_data;

/* {{{ php_crypto_stream_write */
static size_t php_crypto_stream_write(php_stream *stream, const char *buf, size_t count TSRMLS_DC)
{
	
}
/* }}} */

/* {{{ php_crypto_stream_read */
static size_t php_crypto_stream_read(php_stream *stream, char *buf, size_t count TSRMLS_DC)
{
	
}
/* }}} */

/* {{{ php_crypto_stream_close */
static int php_crypto_stream_close(php_stream *stream, int close_handle TSRMLS_DC)
{
	
}
/* }}} */

/* {{{ php_crypto_stream_flush */
static int php_crypto_stream_flush(php_stream *stream TSRMLS_DC)
{
	
}
/* }}} */

/* {{{ php_crypto_stream_seek */
static int php_crypto_stream_seek(php_stream *stream, off_t offset, int whence, off_t *newoffset TSRMLS_DC)
{
	
}
/* }}} */

/* {{{ php_crypto_stream_cast */
static int php_crypto_stream_cast(php_stream *stream, int castas, void **ret TSRMLS_DC)
{
	
}
/* }}} */

php_stream_ops  php_crypto_stream_ops = {
	php_crypto_stream_write, php_crypto_stream_read,
	php_crypto_stream_close, php_crypto_stream_flush,
	"crypto",
	php_crypto_stream_seek,
	php_crypto_stream_cast,
	NULL, /* stat */
	NULL  /* set_option */
};

/* {{{ php_crypto_stream_opener */
static php_stream *php_crypto_stream_opener(php_stream_wrapper *wrapper, const char *path, const char *mode,
		int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	
}
/* }}} */

static php_stream_wrapper_ops php_crypto_stream_wrapper_ops = {
	php_crypto_stream_opener,
	NULL,
	NULL,
	NULL,
	NULL,
	"crypto",
	NULL,
	NULL,
	NULL,
	NULL
};

static php_stream_wrapper php_crypto_stream_wrapper = {
	&php_crypto_stream_wrapper_ops,
	NULL,
	0
};

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_stream)
{
	php_register_url_stream_wrapper("crypto.file", &php_crypto_stream_wrapper TSRMLS_CC);
}
/* }}} */
