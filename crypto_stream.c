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

/* crypto stream data */
typedef struct {
	BIO *bio;
} php_crypto_stream_data;

/* {{{ php_crypto_stream_write */
static size_t php_crypto_stream_write(php_stream *stream, const char *buf, size_t count TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	int bytes_written = BIO_write(data->bio, buf, count > INT_MAX ? INT_MAX : count);
	return bytes_written <= 0 ? 0 : (size_t) bytes_written;
}
/* }}} */

/* {{{ php_crypto_stream_read */
static size_t php_crypto_stream_read(php_stream *stream, char *buf, size_t count TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	int bytes_read = BIO_read(data->bio, buf, count > INT_MAX ? INT_MAX : count);
	if (bytes_read > 0) {
		return (size_t) bytes_read;
	}
	stream->eof = !BIO_should_retry(data->bio);
	return 0;
}
/* }}} */

/* {{{ php_crypto_stream_close */
static int php_crypto_stream_close(php_stream *stream, int close_handle TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	BIO_free_all(data->bio);
	efree(data);
	return 0;
}
/* }}} */

/* {{{ php_crypto_stream_flush */
static int php_crypto_stream_flush(php_stream *stream TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	BIO_flush(data->bio);
	return 0;
}
/* }}} */

/* {{{ php_crypto_stream_seek */
static int php_crypto_stream_seek(php_stream *stream, off_t offset, int whence, off_t *newoffset TSRMLS_DC)
{
	int ret;
	php_crypto_stream_data *data;
		
	/* The only supported value in OpenSSL */
	if (whence != SEEK_SET) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Only SEEK_SET is allowed");
		return -1;
	}
	/* Don't allow offset greater than INT_MAX due to BIO_ctrl return value casting */
	if (offset > INT_MAX) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The offset greater than %d is not allowed", INT_MAX);
		return -1;
	}
	
	data = (php_crypto_stream_data *) stream->abstract;
	ret = BIO_seek(data->bio, offset);
	*newoffset = (off_t) BIO_tell(data->bio);
	return ret;
}
/* }}} */

/* crypto stream options */
php_stream_ops  php_crypto_stream_ops = {
	php_crypto_stream_write, php_crypto_stream_read,
	php_crypto_stream_close, php_crypto_stream_flush,
	"crypto",
	php_crypto_stream_seek,
	NULL, /* cast */
	NULL, /* stat */
	NULL  /* set_option */
};

/* {{{ php_crypto_stream_opener */
static php_stream *php_crypto_stream_opener(php_stream_wrapper *wrapper, const char *path, const char *mode,
		int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	char *realpath;
	php_stream *stream;
	php_crypto_stream_data *self;
	
	if (strncasecmp(PHP_CRYPTO_STREAM_FILE_SCHEME, path, PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE) == 0) {
		path += PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE;
	}
	
	if (((options & STREAM_DISABLE_OPEN_BASEDIR) == 0) && php_check_open_basedir(path TSRMLS_CC)) {
		return NULL;
	}
	
	if (options & STREAM_ASSUME_REALPATH) {
		realpath = estrdup(path);
	} else if ((realpath = expand_filepath(path, NULL TSRMLS_CC)) == NULL) {
		return NULL;
	}
	
	self = emalloc(sizeof(*self));
	self->bio = BIO_new_file(realpath, mode);
	if (self->bio == NULL) {
		efree(self);
		efree(realpath);
		return NULL;
	}
	
	stream = php_stream_alloc_rel(&php_crypto_stream_ops, self, 0, mode);
	if (stream) {
		if (opened_path) {
			*opened_path = realpath;
			realpath = NULL;
		}
		if (realpath) {
			efree(realpath);
		}
	}
	return stream;
}
/* }}} */

/* crypto stream wrapper options */
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

/* crypto stream wrapper */
static php_stream_wrapper php_crypto_stream_wrapper = {
	&php_crypto_stream_wrapper_ops,
	NULL,
	0
};

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_stream)
{
	php_register_url_stream_wrapper(PHP_CRYPTO_STREAM_FILE_IDENT, &php_crypto_stream_wrapper TSRMLS_CC);
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */
PHP_MSHUTDOWN_FUNCTION(crypto_stream)
{
	php_unregister_url_stream_wrapper(PHP_CRYPTO_STREAM_FILE_IDENT TSRMLS_CC);
	
	return SUCCESS;
}
/* }}} */
