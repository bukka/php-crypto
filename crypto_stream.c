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

PHP_CRYPTO_ERROR_INFO_BEGIN(Stream)
PHP_CRYPTO_ERROR_INFO_ENTRY(SEEK_OPERATION_FORBIDDEN, "Requested seek operation is forbidden (only SEEK_SET is allowed)")
PHP_CRYPTO_ERROR_INFO_ENTRY(SEEK_OFFSET_HIGH, "The offset greater than %d is not allowed")
PHP_CRYPTO_ERROR_INFO_ENTRY(FILTERS_CONTEXT_TYPE_INVALID, "The filters context field has to be an array")
PHP_CRYPTO_ERROR_INFO_ENTRY(FILTERS_ITEM_CONTEXT_TYPE_INVALID, "The filters item context field has to be an array")
PHP_CRYPTO_ERROR_INFO_ENTRY(FILTER_TYPE_NOT_SUPPLIED, "The filters context param 'type' is required")
PHP_CRYPTO_ERROR_INFO_ENTRY(FILTER_TYPE_INVALID, "The filters type has to be a string")
PHP_CRYPTO_ERROR_INFO_ENTRY(FILTER_TYPE_UNKNOWN, "The filters type '%s' is not known")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_CONTEXT_TYPE_INVALID, "The filters field cipher has to be an array")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_ACTION_NOT_SUPPLIED, "The cipher context parameter 'action' is required")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_ACTION_INVALID, "The cipher context parameter 'action' has to be either 'encode' or 'decode'")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_ALGORITHM_NOT_SUPPLIED, "The cipher context parameter 'algorithm' is required")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_ALGORITHM_TYPE_INVALID, "The cipher algorithm has to be a string")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_KEY_NOT_SUPPLIED, "The cipher context parameter 'key' is required")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_KEY_TYPE_INVALID, "The cipher key has to be a string")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_KEY_LENGTH_INVALID, "The cipher key length must be %d characters")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_IV_NOT_SUPPLIED, "The cipher context parameter 'iv' is required")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_IV_TYPE_INVALID, "The cipher IV has to be a string")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_IV_LENGTH_INVALID, "The cipher IV length must be %d characters")
PHP_CRYPTO_ERROR_INFO_ENTRY(CIPHER_TAG_FORBIDDEN, "The cipher tag can be set only for encryption")
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(CIPHER_TAG_FAILED, "The cipher tag retrieving failed", E_NOTICE)
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(CIPHER_TAG_USELESS, "The cipher tag is useful only for authenticated mode", E_NOTICE)
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(CIPHER_AAD_USELESS, "The cipher AAD is useful only for authenticated mode", E_NOTICE)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_EXTERN_MODULE_GLOBALS(crypto)

/* crypto stream data */
typedef struct {
	BIO *bio;
	zend_bool auth_enc;
} php_crypto_stream_data;

/* {{{ php_crypto_stream_write */
static size_t php_crypto_stream_write(php_stream *stream, const char *buf, size_t count TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	int bytes_written = BIO_write(data->bio, buf, count > INT_MAX ? INT_MAX : count);
	return bytes_written <= 0 ? 0 : (size_t) bytes_written;
}
/* }}} */

/* {{{ php_crypto_stream_auth_get_first_bio */
static int php_crypto_stream_auth_get_first_bio(BIO *bio, BIO **p_auth_bio, EVP_CIPHER_CTX **p_cipher_ctx)
{
	while (bio && (bio = BIO_find_type(bio, BIO_TYPE_CIPHER))) {
		EVP_CIPHER_CTX *cipher_ctx;
		const php_crypto_cipher_mode *mode;
		
		BIO_get_cipher_ctx(bio, &cipher_ctx);
		mode = php_crypto_get_cipher_mode(EVP_CIPHER_CTX_cipher(cipher_ctx));
		if (mode->auth_enc) {
			*p_cipher_ctx = cipher_ctx;
			*p_auth_bio = bio;
			return SUCCESS;
		}
		bio = bio->next_bio;
	}
	return FAILURE;
}
/* }}} */

/* {{{ php_crypto_stream_create_meta_field */
static void inline php_crypto_stream_create_meta_field(char *out, const char *key, const char *value)
{
	char *ptr;
	strcpy(out, key);
	ptr = out + strlen(key);
	memcpy(ptr,  ": ", 2);
	strcpy(ptr + 2, value);
}
/* }}} */

/* {{{ php_crypto_stream_auth_save_tag */
static void php_crypto_stream_set_meta(php_stream *stream, const char *key, const char *value)
{
	char *header;
	size_t len = strlen(key) + strlen(value) + 3;
	
	if (stream->wrapperdata && Z_TYPE_P(stream->wrapperdata) != IS_ARRAY) {
		zval_ptr_dtor(&stream->wrapperdata);
		stream->wrapperdata = NULL;
	}
	if (stream->wrapperdata) {
		HashPosition pos;
		zval **ppz_wrapperdata_item;
		
		for (zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(stream->wrapperdata), &pos);
			zend_hash_get_current_data_ex(Z_ARRVAL_P(stream->wrapperdata), (void **) &ppz_wrapperdata_item, &pos) == SUCCESS;
			zend_hash_move_forward_ex(Z_ARRVAL_P(stream->wrapperdata), &pos)
		) {
			if (Z_TYPE_PP(ppz_wrapperdata_item) == IS_STRING &&
				(size_t) Z_STRLEN_PP(ppz_wrapperdata_item) > strlen(key) &&
				!strncmp(Z_STRVAL_PP(ppz_wrapperdata_item), key, strlen(key))
			) {
				if (len > (size_t) Z_STRLEN_PP(ppz_wrapperdata_item)) {
					Z_STRVAL_PP(ppz_wrapperdata_item) = erealloc(Z_STRVAL_PP(ppz_wrapperdata_item), len);
				}
				php_crypto_stream_create_meta_field(Z_STRVAL_PP(ppz_wrapperdata_item), key, value);
				return;
			}
			
		}
	} else {
		MAKE_STD_ZVAL(stream->wrapperdata);
		array_init(stream->wrapperdata);
	}
	
	header = emalloc(len);
	php_crypto_stream_create_meta_field(header, key, value);
	add_next_index_string(stream->wrapperdata, header, 0);
	
}
/* }}} */

/* {{{ php_crypto_stream_auth_save_tag */
static void php_crypto_stream_auth_save_tag(php_stream *stream, EVP_CIPHER_CTX *cipher_ctx TSRMLS_DC)
{
	char hex_tag[PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX * 2 + 1];
	unsigned char bin_tag[PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX + 1];
	const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode(EVP_CIPHER_CTX_cipher(cipher_ctx));
	if (EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->auth_get_tag_flag, PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX, &bin_tag[0])) {
		php_crypto_hash_bin2hex(&hex_tag[0], &bin_tag[0], PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX);
		php_crypto_stream_set_meta(stream, PHP_CRYPTO_STREAM_META_AUTH_TAG, &hex_tag[0]);
	} else {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_TAG_FAILED));
	}
}
/* }}} */

/* {{{ php_crypto_stream_auth_save_result */
static void php_crypto_stream_auth_save_result(php_stream *stream, int ok)
{
	php_crypto_stream_set_meta(stream, PHP_CRYPTO_STREAM_META_AUTH_RESULT, ok ? "success" : "failure");
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
	if (data->auth_enc && stream->eof) {
		EVP_CIPHER_CTX *cipher_ctx;
		BIO *auth_bio;
		if (php_crypto_stream_auth_get_first_bio(data->bio, &auth_bio, &cipher_ctx) == SUCCESS) {
			if (cipher_ctx->encrypt) {
				/* encryption - save auth tag */
				php_crypto_stream_auth_save_tag(stream, cipher_ctx TSRMLS_CC);
			} else {
				/* decryption - save auth result */
				int ok = (int) BIO_ctrl(auth_bio, BIO_C_GET_CIPHER_STATUS, 0, NULL);
				php_crypto_stream_auth_save_result(stream, ok);
			}
		}
	}
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
	/* eof is set when the last read is done (this prevents infinite loop in cipher bio) */
	if (!stream->eof) {
		int ok = BIO_flush(data->bio);
		if (data->auth_enc) {
			EVP_CIPHER_CTX *cipher_ctx;
			BIO *auth_bio;
			if (php_crypto_stream_auth_get_first_bio(data->bio, &auth_bio, &cipher_ctx) == SUCCESS) {
				if (cipher_ctx->encrypt) {
					/* encryption - save auth tag */
					php_crypto_stream_auth_save_tag(stream, cipher_ctx TSRMLS_CC);
				} else {
					/* decryption - save auth result */
					php_crypto_stream_auth_save_result(stream, ok);
				}
			}
		}
	}
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
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(SEEK_OPERATION_FORBIDDEN));
		return -1;
	}
	/* Don't allow offset greater than INT_MAX due to BIO_ctrl return value casting */
	if (offset > INT_MAX) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(SEEK_OFFSET_HIGH), INT_MAX);
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
static int php_crypto_stream_set_cipher(php_crypto_stream_data *data, zval **ppz_cipher TSRMLS_DC)
{
	zval **ppz_action, **ppz_alg, **ppz_mode, **ppz_key_size, **ppz_key, **ppz_iv, **ppz_tag, **ppz_aad;
	BIO *cipher_bio;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cipher_ctx;
	const php_crypto_cipher_mode *mode;
	unsigned char *aad;
	int enc = 1, aad_len;
	
	if (Z_TYPE_PP(ppz_cipher) != IS_ARRAY) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_CONTEXT_TYPE_INVALID));
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "action", sizeof("action"), (void **) &ppz_action) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ACTION_NOT_SUPPLIED));
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_action) != IS_STRING || 
			!(strncmp(Z_STRVAL_PP(ppz_action), "encrypt", sizeof("encrypt") - 1) == 0 ||
				(enc = strncmp(Z_STRVAL_PP(ppz_action),  "decrypt", sizeof("decrypt") - 1)) == 0)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ACTION_INVALID));
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "algorithm", sizeof("algorithm"), (void **) &ppz_alg) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ALGORITHM_NOT_SUPPLIED));
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_alg) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ALGORITHM_TYPE_INVALID));
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
		return FAILURE;
	}
	
	mode = php_crypto_get_cipher_mode(cipher);
	if (mode->auth_enc) {
		data->auth_enc = 1;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "key", sizeof("key"), (void **) &ppz_key) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_NOT_SUPPLIED));
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_key) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_TYPE_INVALID));
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "iv", sizeof("iv"), (void **) &ppz_iv) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_NOT_SUPPLIED));
		return FAILURE;
	}
	if (Z_TYPE_PP(ppz_iv) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_TYPE_INVALID));
		return FAILURE;
	}
	
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "tag", sizeof("tag"), (void **) &ppz_tag) == FAILURE) {
		ppz_tag = NULL;
	} else if (!mode->auth_enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_TAG_USELESS));
	} else if (enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_TAG_FORBIDDEN));
		return FAILURE;
	}
	if (zend_hash_find(Z_ARRVAL_PP(ppz_cipher), "aad", sizeof("aad"), (void **) &ppz_aad) == FAILURE) {
		ppz_aad = NULL;
	} else if (!mode->auth_enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_AAD_USELESS));
	}
	
	cipher_bio = BIO_new(BIO_f_cipher());
	BIO_set_cipher(cipher_bio, cipher, NULL, NULL, enc);
	BIO_push(cipher_bio, data->bio);
	data->bio = cipher_bio;
		
	BIO_get_cipher_ctx(cipher_bio, &cipher_ctx);
	
	/* check key length */
	if (Z_STRLEN_PP(ppz_key) != EVP_CIPHER_key_length(cipher) &&
			!EVP_CIPHER_CTX_set_key_length(cipher_ctx, Z_STRLEN_PP(ppz_key))) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_LENGTH_INVALID), EVP_CIPHER_key_length(cipher));
		return FAILURE;
	}
	/* check iv length */
	if (Z_STRLEN_PP(ppz_iv) != EVP_CIPHER_iv_length(cipher) &&
			(!mode->auth_enc || !EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->auth_ivlen_flag, Z_STRLEN_PP(ppz_iv), NULL))) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_LENGTH_INVALID), EVP_CIPHER_iv_length(cipher));
		return FAILURE;
	}
	
	/* initialize cipher with key and iv */
	if (!EVP_CipherInit_ex(cipher_ctx, NULL, NULL,
			(unsigned char *) Z_STRVAL_PP(ppz_key), (unsigned char *) Z_STRVAL_PP(ppz_iv), enc)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_INIT_FAILED));
		return FAILURE;
	}
	
	if (!mode->auth_enc) {
		return SUCCESS;
	}
	
	/* authentication tag */
	if (ppz_tag && php_crypto_cipher_set_tag(cipher_ctx, mode, 
			(unsigned char *) Z_STRVAL_PP(ppz_tag), Z_STRLEN_PP(ppz_tag) TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}
	/* additional authentication data */
	if (ppz_aad) {
		aad =  (unsigned char *) Z_STRVAL_PP(ppz_aad);
		aad_len = Z_STRLEN_PP(ppz_aad);
	} else {
		aad = NULL;
		aad_len = 0;
	}
	if (php_crypto_cipher_write_aad(cipher_ctx, aad, aad_len TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}
	
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_stream_opener */
static php_stream *php_crypto_stream_opener(php_stream_wrapper *wrapper, php_crypto_stream_opener_char_t *path,
		php_crypto_stream_opener_char_t *mode, int options, char **opened_path, php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	char *realpath;
	zval **ppz_filter;
	php_stream *stream;
	php_crypto_stream_data *self;
	php_crypto_error_action initial_error_action = PHP_CRYPTO_G(error_action);
	
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
	
	PHP_CRYPTO_G(error_action) = PHP_CRYPTO_STREAM_ERROR_ACTION;
	
	self = emalloc(sizeof(*self));
	self->bio = BIO_new_file(realpath, mode);
	if (self->bio == NULL) {
		goto opener_error_on_bio_init;
	}
	
	if (php_stream_context_get_option(context, PHP_CRYPTO_STREAM_WRAPPER_NAME, "filters", &ppz_filter) != FAILURE) {
		HashPosition pos;
		zval **ppz_filter_item, **ppz_type;
		
		if (Z_TYPE_PP(ppz_filter) != IS_ARRAY) {
			php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTERS_CONTEXT_TYPE_INVALID));
			goto opener_error;
		}
		for (zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(ppz_filter), &pos);
			zend_hash_get_current_data_ex(Z_ARRVAL_PP(ppz_filter), (void **) &ppz_filter_item, &pos) == SUCCESS;
			zend_hash_move_forward_ex(Z_ARRVAL_PP(ppz_filter), &pos)
		) {
			if (Z_TYPE_PP(ppz_filter_item) != IS_ARRAY) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTERS_ITEM_CONTEXT_TYPE_INVALID));
				goto opener_error;
			}
			if (zend_hash_find(Z_ARRVAL_PP(ppz_filter_item), "type", sizeof("type"), (void **) &ppz_type) == FAILURE) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_NOT_SUPPLIED));
				goto opener_error;
			}
			if (Z_TYPE_PP(ppz_type) != IS_STRING) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_INVALID));
				goto opener_error;
			}
			/* call filter handler for supplied type */
			if (strncmp(Z_STRVAL_PP(ppz_type), "cipher", sizeof("cipher") - 1) == 0) {
				if (php_crypto_stream_set_cipher(self, ppz_filter_item TSRMLS_CC) == FAILURE) {
					goto opener_error;
				}
			} else {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_UNKNOWN));
				goto opener_error;
			}
		}
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

opener_error:
	BIO_free_all(self->bio);
opener_error_on_bio_init:
	PHP_CRYPTO_G(error_action) = initial_error_action;
	efree(self);
	efree(realpath);
	return NULL;
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
