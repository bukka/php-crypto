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
#include "php_crypto_alg.h"

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

/* {{{ php_crypto_stream_set_cipher */
static int php_crypto_stream_set_cipher(const char *wrappername, php_stream_context *context TSRMLS_DC)
{
	zval **ppz_cipher, **ppz_action, **ppz_alg, **ppz_mode, **ppz_key_size, **ppz_key, **ppz_iv, **ppz_tag, **ppz_aad;
	const EVP_CIPHER *cipher;
	const php_crypto_cipher_mode *mode;
	int enc = 1;
	
	if (php_stream_context_get_option(context, wrappername, "cipher", &ppz_cipher) == FAILURE) {
		/* no need to do anything */
		return SUCCESS;
	}
	
	if (Z_TYPE_PP(ppz_cipher) != IS_ARRAY) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context has to be an array");
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "action", sizeof("action"), (void **) &ppz_action) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context parameter 'action' is required");
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_action) != IS_STRING || 
			strncmp(Z_STRVAL_PP(ppz_action), "encode", 6) != 0 ||
			(enc = strncmp(Z_STRVAL_PP(ppz_action), "decode", 6)) != 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context parameter 'action' has to be either 'encode' or 'decode'");
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "algorithm", sizeof("algorithm"), (void **) &ppz_alg) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context parameter 'algorithm' is required");
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_alg) != IS_STRING) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher algorithm has to be string");
		return FAILURE;
	}
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "mode", sizeof("mode"), (void **) &ppz_mode) == FAILURE) {
		ppz_mode = NULL;
	}
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "key_size", sizeof("key_size"), (void **) &ppz_key_size) == FAILURE) {
		ppz_key_size = NULL;
	}
	cipher = php_crypto_get_cipher_algorithm_from_params(
		Z_STRVAL_PP(ppz_alg), Z_STRLEN_PP(ppz_alg), ppz_mode ? *ppz_mode: NULL, ppz_key_size ? *ppz_key_size: NULL TSRMLS_CC);
	if (!cipher) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher algorithm not found");
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "key", sizeof("key"), (void **) &ppz_key) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context parameter 'key' is required");
		return FAILURE;
	}
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "iv", sizeof("iv"), (void **) &ppz_iv) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The cipher context parameter 'iv' is required");
		return FAILURE;
	}
	
	mode = php_crypto_get_cipher_mode(cipher);
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "tag", sizeof("tag"), (void **) &ppz_tag) == FAILURE) {
		ppz_tag = NULL;
	} else if (!mode->auth_enc) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Tag is useful only for authenticated mode");
	}
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "aad", sizeof("aad"), (void **) &ppz_aad) == FAILURE) {
		ppz_aad = NULL;
	} else if (!mode->auth_enc) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "AAD is useful only for authenticated mode");
	}
	
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_stream_opener */
static php_stream *php_crypto_stream_opener(php_stream_wrapper *wrapper, php_crypto_stream_opener_char_t *path,
		php_crypto_stream_opener_char_t *mode, int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	char *realpath;
	const char *wrappername;
	php_stream *stream;
	php_crypto_stream_data *self;
	
	if (strncasecmp(PHP_CRYPTO_STREAM_FILE_SCHEME, path, PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE) == 0) {
		path += PHP_CRYPTO_STREAM_FILE_SCHEME_SIZE;
		wrappername = PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME;
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
	
	if (php_crypto_stream_set_cipher(wrappername, context TSRMLS_CC)) {
		BIO_free_all(self->bio);
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
	php_register_url_stream_wrapper(PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME, &php_crypto_stream_wrapper TSRMLS_CC);
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */
PHP_MSHUTDOWN_FUNCTION(crypto_stream)
{
	php_unregister_url_stream_wrapper(PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME TSRMLS_CC);
	
	return SUCCESS;
}
/* }}} */
