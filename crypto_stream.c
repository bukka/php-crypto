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
#include "php_crypto_stream.h"
#include "php_crypto_cipher.h"
#include "php_crypto_hash.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

PHP_CRYPTO_ERROR_INFO_BEGIN(Stream)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	SEEK_OPERATION_FORBIDDEN,
	"Requested seek operation is forbidden (only SEEK_SET is allowed)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	SEEK_OFFSET_HIGH,
	"The offset greater than %d is not allowed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILTERS_CONTEXT_TYPE_INVALID,
	"The filters context field has to be an array"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILTERS_ITEM_CONTEXT_TYPE_INVALID,
	"The filters item context field has to be an array"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILTER_TYPE_NOT_SUPPLIED,
	"The filters context param 'type' is required"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILTER_TYPE_INVALID,
	"The filters type has to be a string"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FILTER_TYPE_UNKNOWN,
	"The filters type '%s' is not known"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_CONTEXT_TYPE_INVALID,
	"The filters field cipher has to be an array"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_ACTION_NOT_SUPPLIED,
	"The cipher context parameter 'action' is required"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_ACTION_INVALID,
	"The cipher context parameter 'action' has to be either 'encode' or 'decode'"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_ALGORITHM_NOT_SUPPLIED,
	"The cipher context parameter 'algorithm' is required"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_ALGORITHM_TYPE_INVALID,
	"The cipher algorithm has to be a string"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_KEY_NOT_SUPPLIED,
	"The cipher context parameter 'key' is required"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_MODE_NOT_SUPPORTED,
	"The %s mode is not supported in stream"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_KEY_TYPE_INVALID,
	"The cipher key has to be a string"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_KEY_LENGTH_INVALID,
	"The cipher key length must be %d characters"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_IV_NOT_SUPPLIED,
	"The cipher context parameter 'iv' is required"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_IV_TYPE_INVALID,
	"The cipher IV has to be a string"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_IV_LENGTH_INVALID,
	"The cipher IV length must be %d characters"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	CIPHER_TAG_FORBIDDEN,
	"The cipher tag can be set only for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(
	CIPHER_TAG_FAILED,
	"The cipher tag retrieving failed",
	E_NOTICE
)
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(
	CIPHER_TAG_USELESS,
	"The cipher tag is useful only for authenticated mode",
	E_NOTICE
)
PHP_CRYPTO_ERROR_INFO_ENTRY_EX(
	CIPHER_AAD_USELESS,
	"The cipher AAD is useful only for authenticated mode",
	E_NOTICE
)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_EXTERN_MODULE_GLOBALS(crypto)

/* crypto stream data */
typedef struct {
	BIO *bio;
	zend_bool auth_enc;
	zend_bool is_encrypting;
} php_crypto_stream_data;

/* {{{ php_crypto_stream_write */
static size_t php_crypto_stream_write(php_stream *stream,
		const char *buf, size_t count TSRMLS_DC)
{
	php_crypto_stream_data *data = (php_crypto_stream_data *) stream->abstract;
	int bytes_written = BIO_write(data->bio, buf, count > INT_MAX ? INT_MAX : count);

	return bytes_written <= 0 ? 0 : (size_t) bytes_written;
}
/* }}} */

/* {{{ php_crypto_stream_auth_get_first_bio */
static int php_crypto_stream_auth_get_first_bio(
		BIO *bio, BIO **p_auth_bio, EVP_CIPHER_CTX **p_cipher_ctx)
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
		bio = BIO_next(bio);
	}

	return FAILURE;
}
/* }}} */

/* {{{ php_crypto_stream_create_meta_field */
static void inline php_crypto_stream_create_meta_field(
		char *out, const char *key, const char *value)
{
	char *ptr;
	strcpy(out, key);
	ptr = out + strlen(key);
	memcpy(ptr,  ": ", 2);
	strcpy(ptr + 2, value);
}
/* }}} */

/* {{{ php_crypto_stream_auth_save_tag */
static void php_crypto_stream_set_meta(php_stream *stream,
		const char *key, const char *value)
{
	PHPC_STR_DECLARE(header);
	size_t len = strlen(key) + strlen(value) + 2;
	zval *p_wrapper;

	if (PHPC_STREAM_WRAPPERDATA_ISSET(stream) && PHPC_TYPE(stream->wrapperdata) != IS_ARRAY) {
		PHPC_STREAM_WRAPPERDATA_UNSET(stream);
	}
	if (PHPC_STREAM_WRAPPERDATA_ISSET(stream)) {
		phpc_val *ppv_wrapperdata_item;

		PHPC_HASH_FOREACH_VAL(PHPC_ARRVAL(stream->wrapperdata), ppv_wrapperdata_item) {
			if (PHPC_TYPE_P(ppv_wrapperdata_item) == IS_STRING &&
				(size_t) PHPC_STRLEN_P(ppv_wrapperdata_item) > strlen(key) &&
				!strncmp(PHPC_STRVAL_P(ppv_wrapperdata_item), key, strlen(key))
			) {
				if (len != (size_t) PHPC_STRLEN_P(ppv_wrapperdata_item)) {
					PHPC_STR_DECLARE(item);

					PHPC_STR_INIT(item,
							PHPC_STRVAL_P(ppv_wrapperdata_item),
							PHPC_STRLEN_P(ppv_wrapperdata_item));
					zval_ptr_dtor(ppv_wrapperdata_item);
					PHPC_VAL_STR(*ppv_wrapperdata_item, item);
				}
				php_crypto_stream_create_meta_field(
						PHPC_STRVAL_P(ppv_wrapperdata_item), key, value);
				return;
			}

		} PHPC_HASH_FOREACH_END();

		PHPC_VAL_TO_PZVAL(stream->wrapperdata, p_wrapper);
	} else {
		PHPC_STREAM_WRAPPERDATA_ALLOC(stream);
		PHPC_VAL_TO_PZVAL(stream->wrapperdata, p_wrapper);
		PHPC_ARRAY_INIT(p_wrapper);
	}

	PHPC_STR_ALLOC(header, len);
	php_crypto_stream_create_meta_field(PHPC_STR_VAL(header), key, value);
	PHPC_ARRAY_ADD_NEXT_INDEX_STR(p_wrapper, header);

}
/* }}} */

/* {{{ php_crypto_stream_auth_save_tag */
static void php_crypto_stream_auth_save_tag(php_stream *stream,
		EVP_CIPHER_CTX *cipher_ctx TSRMLS_DC)
{
	char hex_tag[PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX * 2 + 1];
	unsigned char bin_tag[PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX + 1];
	const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode(
			EVP_CIPHER_CTX_cipher(cipher_ctx));
	if (EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->auth_get_tag_flag,
			PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX, &bin_tag[0])) {
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
	php_crypto_stream_set_meta(
			stream,
			PHP_CRYPTO_STREAM_META_AUTH_RESULT,
			ok ? "success" : "failure");
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
			if (data->is_encrypting) {
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
				if (data->is_encrypting) {
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
static int php_crypto_stream_seek(php_stream *stream,
		phpc_off_t offset, int whence, phpc_off_t *newoffset TSRMLS_DC)
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
	*newoffset = (phpc_off_t) BIO_tell(data->bio);
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
static int php_crypto_stream_set_cipher(php_crypto_stream_data *data,
		phpc_val *ppv_cipher TSRMLS_DC)
{
	phpc_val *ppv_action, *ppv_alg, *ppv_mode;
	phpc_val *ppv_key_size, *ppv_key, *ppv_iv, *ppv_tag, *ppv_aad;
	zval *pz_mode, *pz_key_size;
	BIO *cipher_bio;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *cipher_ctx;
	const php_crypto_cipher_mode *mode;
	unsigned char *aad;
	int enc = 1, aad_len;

	if (PHPC_TYPE_P(ppv_cipher) != IS_ARRAY) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_CONTEXT_TYPE_INVALID));
		return FAILURE;
	}

	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "action", ppv_action)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ACTION_NOT_SUPPLIED));
		return FAILURE;
	}
	if (PHPC_TYPE_P(ppv_action) != IS_STRING ||
			!(strncmp(PHPC_STRVAL_P(ppv_action), "encrypt", sizeof("encrypt") - 1) == 0 ||
			 (enc = strncmp(PHPC_STRVAL_P(ppv_action),  "decrypt", sizeof("decrypt") - 1)) == 0)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ACTION_INVALID));
		return FAILURE;
	}
	data->is_encrypting = enc;

	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "algorithm", ppv_alg)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ALGORITHM_NOT_SUPPLIED));
		return FAILURE;
	}
	if (PHPC_TYPE_P(ppv_alg) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_ALGORITHM_TYPE_INVALID));
		return FAILURE;
	}
	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "mode", ppv_mode)) {
		ppv_mode = NULL;
	}
	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "key_size", ppv_key_size)) {
		ppv_key_size = NULL;
	}
	if (ppv_mode) {
		PHPC_PVAL_TO_PZVAL(ppv_mode, pz_mode);
	} else {
		pz_mode = NULL;
	}
	if (ppv_key_size) {
		PHPC_PVAL_TO_PZVAL(ppv_key_size, pz_key_size);
	} else {
		pz_key_size = NULL;
	}
	cipher = php_crypto_get_cipher_algorithm_from_params(
			PHPC_STRVAL_P(ppv_alg), PHPC_STRLEN_P(ppv_alg), pz_mode, pz_key_size TSRMLS_CC);
	if (!cipher) {
		return FAILURE;
	}

	mode = php_crypto_get_cipher_mode(cipher);
	if (mode->auth_inlen_init) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_MODE_NOT_SUPPORTED), mode->name);
		return FAILURE;
	}
	if (mode->auth_enc) {
		data->auth_enc = 1;
	}

	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "key", ppv_key)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_NOT_SUPPLIED));
		return FAILURE;
	}
	if (PHPC_TYPE_P(ppv_key) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_TYPE_INVALID));
		return FAILURE;
	}

	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "iv", ppv_iv)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_NOT_SUPPLIED));
		return FAILURE;
	}
	if (PHPC_TYPE_P(ppv_iv) != IS_STRING) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_TYPE_INVALID));
		return FAILURE;
	}

	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "tag", ppv_tag)) {
		ppv_tag = NULL;
	} else if (!mode->auth_enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_TAG_USELESS));
	} else if (enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_TAG_FORBIDDEN));
		return FAILURE;
	}
	if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_cipher), "aad", ppv_aad)) {
		ppv_aad = NULL;
	} else if (!mode->auth_enc) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_AAD_USELESS));
	}

	cipher_bio = BIO_new(BIO_f_cipher());
	BIO_set_cipher(cipher_bio, cipher, NULL, NULL, enc);
	BIO_push(cipher_bio, data->bio);
	data->bio = cipher_bio;

	BIO_get_cipher_ctx(cipher_bio, &cipher_ctx);

	/* check key length */
	if (PHPC_STRLEN_P(ppv_key) != EVP_CIPHER_key_length(cipher) &&
			!EVP_CIPHER_CTX_set_key_length(cipher_ctx, PHPC_STRLEN_P(ppv_key))) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_KEY_LENGTH_INVALID),
				EVP_CIPHER_key_length(cipher));
		return FAILURE;
	}
	/* check iv length */
	if (PHPC_STRLEN_P(ppv_iv) != EVP_CIPHER_iv_length(cipher) &&
			(!mode->auth_enc || !EVP_CIPHER_CTX_ctrl(
				cipher_ctx, mode->auth_ivlen_flag, PHPC_STRLEN_P(ppv_iv), NULL))) {
		php_crypto_error_ex(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_IV_LENGTH_INVALID),
				EVP_CIPHER_iv_length(cipher));
		return FAILURE;
	}

	/* initialize cipher with key and iv */
	if (!EVP_CipherInit_ex(cipher_ctx, NULL, NULL,
			(unsigned char *) PHPC_STRVAL_P(ppv_key),
			(unsigned char *) PHPC_STRVAL_P(ppv_iv), enc)) {
		php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(CIPHER_INIT_FAILED));
		return FAILURE;
	}

	if (!mode->auth_enc) {
		return SUCCESS;
	}

	/* authentication tag */
	if (ppv_tag && php_crypto_cipher_set_tag(cipher_ctx, mode,
			(unsigned char *) PHPC_STRVAL_P(ppv_tag),
			PHPC_STRLEN_P(ppv_tag) TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}
	/* additional authentication data */
	if (ppv_aad) {
		aad =  (unsigned char *) PHPC_STRVAL_P(ppv_aad);
		aad_len = PHPC_STRLEN_P(ppv_aad);
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
static php_stream *php_crypto_stream_opener(php_stream_wrapper *wrapper,
		phpc_stream_opener_char_t *path, phpc_stream_opener_char_t *mode, int options,
		PHPC_STR_ARG_PTR_VAL(p_opened_path), php_stream_context *context STREAMS_DC TSRMLS_DC)
{
	char *realpath;
	phpc_val *ppv_filter;
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

	if (PHPC_STREAM_CONTEXT_GET_OPTION_IN_COND(context,
			PHP_CRYPTO_STREAM_WRAPPER_NAME, "filters", ppv_filter)) {
		phpc_val *ppv_filter_item, *ppv_type;

		if (PHPC_TYPE_P(ppv_filter) != IS_ARRAY) {
			php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTERS_CONTEXT_TYPE_INVALID));
			goto opener_error;
		}
		PHPC_HASH_FOREACH_VAL(PHPC_ARRVAL_P(ppv_filter), ppv_filter_item) {
			if (PHPC_TYPE_P(ppv_filter_item) != IS_ARRAY) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTERS_ITEM_CONTEXT_TYPE_INVALID));
				goto opener_error;
			}
			if (!PHPC_HASH_CSTR_FIND_IN_COND(PHPC_ARRVAL_P(ppv_filter_item), "type", ppv_type)) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_NOT_SUPPLIED));
				goto opener_error;
			}
			if (PHPC_TYPE_P(ppv_type) != IS_STRING) {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_INVALID));
				goto opener_error;
			}
			/* call filter handler for supplied type */
			if (strncmp(PHPC_STRVAL_P(ppv_type), "cipher", sizeof("cipher") - 1) == 0) {
				if (php_crypto_stream_set_cipher(self, ppv_filter_item TSRMLS_CC) == FAILURE) {
					goto opener_error;
				}
			} else {
				php_crypto_error(PHP_CRYPTO_STREAM_ERROR_ARGS(FILTER_TYPE_UNKNOWN));
				goto opener_error;
			}
		} PHPC_HASH_FOREACH_END();
	}

	stream = php_stream_alloc_rel(&php_crypto_stream_ops, self, 0, mode);
	if (stream) {
		if (PHPC_STR_EXISTS(p_opened_path)) {
			PHPC_STR_DECLARE(opened_path);
			PHPC_STR_INIT(opened_path, realpath, strlen(realpath));
			PHPC_STR_DEREF_VAL(p_opened_path) = PHPC_STR_PASS_VAL(opened_path);
		}

		efree(realpath);
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
	php_register_url_stream_wrapper(PHP_CRYPTO_STREAM_FILE_WRAPPER_NAME,
			&php_crypto_stream_wrapper TSRMLS_CC);

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
