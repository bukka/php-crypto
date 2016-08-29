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
#include "php_crypto_base64.h"
#include "zend_exceptions.h"

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline EVP_ENCODE_CTX *EVP_ENCODE_CTX_new()
{
	EVP_ENCODE_CTX *ctx = OPENSSL_malloc(sizeof(EVP_ENCODE_CTX));

	return ctx;
}

static inline void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)
{
	OPENSSL_free(ctx);
}

static inline int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, EVP_ENCODE_CTX *sctx)
{
	memcpy(dctx, sctx, sizeof (EVP_ENCODE_CTX));

	return 1;
}

static inline int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx)
{
	return ctx->num;
}

#define EVP_ENCODE_LENGTH(l) (((l+2)/3*4)+(l/48+1)*2+80)
#define EVP_DECODE_LENGTH(l) ((l+3)/4*3+80)

#endif

PHP_CRYPTO_EXCEPTION_DEFINE(Base64)
PHP_CRYPTO_ERROR_INFO_BEGIN(Base64)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	ENCODE_UPDATE_FORBIDDEN,
	"The object is already used for decoding"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	ENCODE_FINISH_FORBIDDEN,
	"The object has not been intialized for encoding"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DECODE_UPDATE_FORBIDDEN,
	"The object is already used for encoding"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DECODE_FINISH_FORBIDDEN,
	"The object has not been intialized for decoding"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DECODE_UPDATE_FAILED,
	"Base64 decoded string does not contain valid characters"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INPUT_DATA_LENGTH_HIGH,
	"Input data length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_base64_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_base64_object_methods[] = {
	PHP_CRYPTO_ME(
		Base64, encode,
		arginfo_crypto_base64_data,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, decode,
		arginfo_crypto_base64_data,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, __construct,
		NULL,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, encodeUpdate,
		arginfo_crypto_base64_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, encodeFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, decodeUpdate,
		arginfo_crypto_base64_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Base64, decodeFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_base64_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_base64);

/* {{{ crypto_base64 free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_base64)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_base64);

	EVP_ENCODE_CTX_free(PHPC_THIS->ctx);

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_base64 create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_base64)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_base64);

	/* allocate encode context */
	PHPC_THIS->ctx = EVP_ENCODE_CTX_new();

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(crypto_base64);
}
/* }}} */

/* {{{ crypto_base64 create object handler */
PHPC_OBJ_HANDLER_CREATE(crypto_base64)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(crypto_base64);
}
/* }}} */

/* {{{ crypto_base64 clone object handler */
PHPC_OBJ_HANDLER_CLONE(crypto_base64)
{
	PHPC_OBJ_HANDLER_CLONE_INIT(crypto_base64);

	PHPC_THAT->status = PHPC_THIS->status;
	EVP_ENCODE_CTX_copy(PHPC_THAT->ctx, PHPC_THIS->ctx);

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

#define PHP_CRYPTO_DECLARE_BASE64_E_CONST(aconst) \
	zend_declare_class_constant_long(php_crypto_base64_exception_ce, \
		#aconst, sizeof(#aconst)-1, PHP_CRYPTO_BASE64_E(aconst) TSRMLS_CC)

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_base64)
{
	zend_class_entry ce;

	/* Base64 class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Base64), php_crypto_base64_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, crypto_base64);
	php_crypto_base64_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(crypto_base64);
	PHPC_OBJ_SET_HANDLER_OFFSET(crypto_base64);
	PHPC_OBJ_SET_HANDLER_FREE(crypto_base64);
	PHPC_OBJ_SET_HANDLER_CLONE(crypto_base64);

	/* Base64Exception class */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, Base64);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Base64);

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_base64_encode_init */
static inline void php_crypto_base64_encode_init(EVP_ENCODE_CTX *ctx)
{
	EVP_EncodeInit(ctx);
}
/* }}} */

/* {{{ php_crypto_base64_encode_update */
static inline int php_crypto_base64_encode_update(
		EVP_ENCODE_CTX *ctx, char *out, int *outl,
		const char *in, phpc_str_size_t in_len TSRMLS_DC)
{
	int inl;

	/* check string length overflow */
	if (php_crypto_str_size_to_int(in_len, &inl) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, INPUT_DATA_LENGTH_HIGH));
		return FAILURE;
	}

	EVP_EncodeUpdate(ctx,
			(unsigned char *) out, outl,
			(const unsigned char *) in, inl);

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_base64_encode_finish */
static inline void php_crypto_base64_encode_finish(
		EVP_ENCODE_CTX *ctx, char *out, int *outl)
{
	EVP_EncodeFinal(ctx, (unsigned char *) out, outl);
}
/* }}} */

/* {{{ php_crypto_base64_decode_init */
static inline void php_crypto_base64_decode_init(EVP_ENCODE_CTX *ctx)
{
	EVP_DecodeInit(ctx);
}
/* }}} */

/* {{{ php_crypto_base64_decode_update */
static inline int php_crypto_base64_decode_update(
		EVP_ENCODE_CTX *ctx, char *out, int *outl,
		const char *in, phpc_str_size_t in_len TSRMLS_DC)
{
	int inl, rc;

	/* check string length overflow */
	if (php_crypto_str_size_to_int(in_len, &inl) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, INPUT_DATA_LENGTH_HIGH));
		return FAILURE;
	}

	rc = EVP_DecodeUpdate(ctx,
			(unsigned char *) out, outl,
			(const unsigned char *) in, inl);
	if (rc < 0) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, DECODE_UPDATE_FAILED));
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_base64_decode_finish */
static inline void php_crypto_base64_decode_finish(EVP_ENCODE_CTX *ctx,
		char *out, int *outl)
{
	EVP_DecodeFinal(ctx, (unsigned char *) out, outl);
}
/* }}} */

/* {{{ proto string Crypto\Base64::encode(string $data)
	Encodes string $data to base64 encoding */
PHP_CRYPTO_METHOD(Base64, encode)
{
	char *in;
	phpc_str_size_t in_len;
	int real_len, final_len, update_len;
	PHPC_STR_DECLARE(out);
	EVP_ENCODE_CTX *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	ctx = EVP_ENCODE_CTX_new();
	php_crypto_base64_encode_init(ctx);
	real_len = EVP_ENCODE_LENGTH(in_len);
	PHPC_STR_ALLOC(out, real_len);
	if (php_crypto_base64_encode_update(
			ctx, PHPC_STR_VAL(out), &update_len, in, in_len TSRMLS_CC) == FAILURE) {
		PHPC_STR_RELEASE(out);
		EVP_ENCODE_CTX_free(ctx);
		RETURN_NULL();
	}
	php_crypto_base64_encode_finish(ctx, PHPC_STR_VAL(out) + update_len, &final_len);
	EVP_ENCODE_CTX_free(ctx);
	final_len += update_len;
	if (real_len > final_len) {
		PHPC_STR_REALLOC(out, final_len);
	}
	PHPC_STR_VAL(out)[final_len] = '\0';
	PHPC_STR_RETURN(out);
}

/* {{{ proto string Crypto\Base64::decode(string $data)
	Decodes base64 string $data to raw encoding */
PHP_CRYPTO_METHOD(Base64, decode)
{
	char *in;
	phpc_str_size_t in_len;
	int real_len, update_len, final_len;
	PHPC_STR_DECLARE(out);
	EVP_ENCODE_CTX *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	ctx = EVP_ENCODE_CTX_new();
	php_crypto_base64_decode_init(ctx);
	real_len = EVP_DECODE_LENGTH(in_len);
	PHPC_STR_ALLOC(out, real_len);

	if (php_crypto_base64_decode_update(ctx, PHPC_STR_VAL(out),
			&update_len, in, in_len TSRMLS_CC) == FAILURE) {
		EVP_ENCODE_CTX_free(ctx);
		RETURN_FALSE;
	}
	php_crypto_base64_decode_finish(ctx, PHPC_STR_VAL(out), &final_len);
	final_len += update_len;
	if (real_len > final_len) {
		PHPC_STR_REALLOC(out, final_len);
	}
	EVP_ENCODE_CTX_free(ctx);
	PHPC_STR_VAL(out)[final_len] = '\0';
	PHPC_STR_RETURN(out);
}

/* {{{ proto Crypto\Base64::__construct()
   Base64 constructor */
PHP_CRYPTO_METHOD(Base64, __construct)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
}

/* {{{ proto Crypto\Base64::encode(string $data)
	Encodes block of characters from $data and saves the reminder of
	the last block to the encoding context */
PHP_CRYPTO_METHOD(Base64, encodeUpdate)
{
	char *in;
	phpc_str_size_t in_len;
	int update_len, real_len;
	PHPC_STR_DECLARE(out);
	PHPC_THIS_DECLARE(crypto_base64);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_base64);

	if (PHPC_THIS->status == PHP_CRYPTO_BASE64_STATUS_DECODE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, ENCODE_UPDATE_FORBIDDEN));
		RETURN_FALSE;
	}
	if (PHPC_THIS->status == PHP_CRYPTO_BASE64_STATUS_CLEAR) {
		php_crypto_base64_encode_init(PHPC_THIS->ctx);
		PHPC_THIS->status = PHP_CRYPTO_BASE64_STATUS_ENCODE;
	}

	real_len = EVP_ENCODE_LENGTH(in_len);
	PHPC_STR_ALLOC(out, real_len);
	if (php_crypto_base64_encode_update(PHPC_THIS->ctx,
			PHPC_STR_VAL(out), &update_len, in, in_len TSRMLS_CC) == FAILURE) {
		PHPC_STR_RELEASE(out);
		RETURN_NULL();
	}
	if (real_len > update_len) {
		PHPC_STR_REALLOC(out, update_len);
	}
	PHPC_STR_VAL(out)[update_len] = '\0';
	PHPC_STR_RETURN(out);
}

/* {{{ proto Crypto\Base64::encodeFinish()
	Encodes characters that left in the encoding context */
PHP_CRYPTO_METHOD(Base64, encodeFinish)
{
	char out[PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN+1];
	int out_len;
	PHPC_THIS_DECLARE(crypto_base64);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_base64);

	if (PHPC_THIS->status != PHP_CRYPTO_BASE64_STATUS_ENCODE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, ENCODE_FINISH_FORBIDDEN));
		RETURN_FALSE;
	}

	php_crypto_base64_encode_finish(PHPC_THIS->ctx, out, &out_len);
	if (out_len == 0) {
		RETURN_EMPTY_STRING();
	}
	out[out_len] = '\0';
	PHPC_CSTRL_RETURN(out, out_len);
}

/* {{{ proto Crypto\Base64::decode(string $data)
	Decodes block of characters from $data and saves the reminder
	of the last block to the encoding context */
PHP_CRYPTO_METHOD(Base64, decodeUpdate)
{
	char *in;
	phpc_str_size_t in_len;
	int update_len, real_len;
	PHPC_STR_DECLARE(out);
	PHPC_THIS_DECLARE(crypto_base64);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_base64);

	if (PHPC_THIS->status == PHP_CRYPTO_BASE64_STATUS_ENCODE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, DECODE_UPDATE_FORBIDDEN));
		RETURN_FALSE;
	}
	if (PHPC_THIS->status == PHP_CRYPTO_BASE64_STATUS_CLEAR) {
		php_crypto_base64_decode_init(PHPC_THIS->ctx);
		PHPC_THIS->status = PHP_CRYPTO_BASE64_STATUS_DECODE;
	}

	real_len = EVP_DECODE_LENGTH(in_len);
	PHPC_STR_ALLOC(out, real_len);
	if (php_crypto_base64_decode_update(PHPC_THIS->ctx,
			PHPC_STR_VAL(out), &update_len, in, in_len TSRMLS_CC) == FAILURE) {
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}
	if (real_len > update_len) {
		PHPC_STR_REALLOC(out, update_len);
	}
	PHPC_STR_VAL(out)[update_len] = '\0';
	PHPC_STR_RETURN(out);
}

/* {{{ proto Crypto\Base64::decodeFinish()
	Decodes characters that left in the encoding context */
PHP_CRYPTO_METHOD(Base64, decodeFinish)
{
	char buff[PHP_CRYPTO_BASE64_DECODING_SIZE_MIN];
	int final_len;
	PHPC_THIS_DECLARE(crypto_base64);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_base64);

	if (PHPC_THIS->status != PHP_CRYPTO_BASE64_STATUS_DECODE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Base64, DECODE_FINISH_FORBIDDEN));
		RETURN_FALSE;
	}

	php_crypto_base64_decode_finish(PHPC_THIS->ctx, buff, &final_len);
	if (final_len == 0) {
		RETURN_EMPTY_STRING();
	}
	buff[final_len] = 0;
	PHPC_CSTRL_RETURN(buff, final_len);
}
