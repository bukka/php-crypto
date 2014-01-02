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
#include "php_crypto_base64.h"
#include "zend_exceptions.h"

#include <openssl/evp.h>

ZEND_BEGIN_ARG_INFO(arginfo_crypto_base64_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_base64_object_methods[] = {
	PHP_CRYPTO_ME(Base64,    encode,            arginfo_crypto_base64_data,  ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    decode,            arginfo_crypto_base64_data,  ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    __construct,       NULL,                        ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    encodeUpdate,      arginfo_crypto_base64_data,  ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    encodeFinish,      NULL,                        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    decodeUpdate,      arginfo_crypto_base64_data,  ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Base64,    decodeFinish,      NULL,                        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_FE_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_base64_ce;

/* exception entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_base64_exception_ce;

/* object handler */
static zend_object_handlers php_crypto_base64_object_handlers;

/* {{{ php_crypto_base64_object_dtor */
static void php_crypto_base64_object_dtor(void *object, zend_object_handle handle TSRMLS_DC)
{
	zend_objects_destroy_object(object, handle TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_base64_object_free */
static void php_crypto_base64_object_free(zend_object *object TSRMLS_DC)
{
	php_crypto_base64_object *intern = (php_crypto_base64_object *) object;
	zend_object_std_dtor(&intern->zo TSRMLS_CC);
	efree(intern->ctx);
	efree(intern);
}
/* }}} */

/* {{{ php_crypto_base64_object_create_ex */
static zend_object_value php_crypto_base64_object_create_ex(zend_class_entry *class_type, php_crypto_base64_object **ptr TSRMLS_DC)
{
	zend_object_value retval;
	php_crypto_base64_object *intern;

	/* Allocate memory for it */
	intern = (php_crypto_base64_object *) emalloc(sizeof(php_crypto_base64_object));
	memset(intern, 0, sizeof(php_crypto_base64_object));
	if (ptr) {
		*ptr = intern;
	}
	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	PHP_CRYPTO_OBJECT_PROPERTIES_INIT(&intern->zo, class_type);

	intern->ctx = (EVP_ENCODE_CTX *) emalloc(sizeof(EVP_ENCODE_CTX));

	retval.handlers = &php_crypto_base64_object_handlers;
	retval.handle = zend_objects_store_put(
		intern,
		(zend_objects_store_dtor_t) php_crypto_base64_object_dtor,
		(zend_objects_free_object_storage_t) php_crypto_base64_object_free,
		NULL TSRMLS_CC);

	return retval;
}
/* }}} */

/* {{{ php_crypto_base64_object_create */
static zend_object_value php_crypto_base64_object_create(zend_class_entry *class_type TSRMLS_DC)
{
	return php_crypto_base64_object_create_ex(class_type, NULL TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_base64_object_clone */
zend_object_value php_crypto_base64_object_clone(zval *this_ptr TSRMLS_DC)
{
	php_crypto_base64_object *new_obj = NULL;
	php_crypto_base64_object *old_obj = (php_crypto_base64_object *) zend_object_store_get_object(this_ptr TSRMLS_CC);
	zend_object_value new_ov = php_crypto_base64_object_create_ex(old_obj->zo.ce, &new_obj TSRMLS_CC);

	zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);
	new_obj->status = old_obj->status;
	memcpy(new_obj->ctx, old_obj->ctx, sizeof (EVP_ENCODE_CTX));

	return new_ov;
}
/* }}} */

#define PHP_CRYPTO_DECLARE_BASE64_E_CONST(aconst) \
	zend_declare_class_constant_long(php_crypto_base64_exception_ce, #aconst, sizeof(#aconst)-1, PHP_CRYPTO_BASE64_E(aconst) TSRMLS_CC)

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_base64)
{
	zend_class_entry ce;

	/* Base64 class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Base64), php_crypto_base64_object_methods);
	ce.create_object = php_crypto_base64_object_create;
	memcpy(&php_crypto_base64_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_crypto_base64_object_handlers.clone_obj = php_crypto_base64_object_clone;
	php_crypto_base64_ce = zend_register_internal_class(&ce TSRMLS_CC);

	/* Base64 Exception class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Base64Exception), NULL);
	php_crypto_base64_exception_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	/* Declare Base64Exception class constants for error codes */
	PHP_CRYPTO_DECLARE_BASE64_E_CONST(ENCODE_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_BASE64_E_CONST(ENCODE_FINISH_STATUS);
	PHP_CRYPTO_DECLARE_BASE64_E_CONST(DECODE_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_BASE64_E_CONST(DECODE_FINISH_STATUS);
	PHP_CRYPTO_DECLARE_BASE64_E_CONST(DECODE_FAILED);

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
static inline void php_crypto_base64_encode_update(EVP_ENCODE_CTX *ctx, char *out, int *outl, const char *in, int inl)
{
	EVP_EncodeUpdate(ctx, (unsigned char *) out, outl, (const unsigned char *) in, inl);
}
/* }}} */

/* {{{ php_crypto_base64_encode_finish */
static inline void php_crypto_base64_encode_finish(EVP_ENCODE_CTX *ctx, char *out, int *outl)
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
static inline int php_crypto_base64_decode_update(EVP_ENCODE_CTX *ctx, char *out, int *outl, const char *in, int inl TSRMLS_DC)
{
	int rc = EVP_DecodeUpdate(ctx, (unsigned char *) out, outl, (const unsigned char *) in, inl);
	if (rc < 0) {
		PHP_CRYPTO_THROW_BASE64_EXCEPTION(DECODE_FAILED, "Base64 decoded string does not contain valid characters");
	}
	return rc;
}
/* }}} */

/* {{{ php_crypto_base64_decode_finish */
static inline void php_crypto_base64_decode_finish(EVP_ENCODE_CTX *ctx, char *out, int *outl)
{
	EVP_DecodeFinal(ctx, (unsigned char *) out, outl);
}
/* }}} */

/* {{{ proto string Crypto\Base64::encode(string $data)
   Encodes string $data to base64 encoding */
PHP_CRYPTO_METHOD(Base64, encode)
{
	char *in, *out;
	int in_len, out_len, final_len;
	EVP_ENCODE_CTX ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	php_crypto_base64_encode_init(&ctx);
	out_len = PHP_CRYPTO_BASE64_ENCODING_SIZE_REAL(in_len, &ctx);
	out = (char *) emalloc(out_len);
	php_crypto_base64_encode_update(&ctx, out, &out_len, in, in_len);
	php_crypto_base64_encode_finish(&ctx, out + out_len, &final_len);
	out_len += final_len;
	out[out_len] = 0;
	RETURN_STRINGL(out, out_len, 0);
}

/* {{{ proto string Crypto\Base64::decode(string $data)
   Decodes base64 string $data to raw encoding */
PHP_CRYPTO_METHOD(Base64, decode)
{
	char *in, *out;
	int in_len, out_len, final_len;
	EVP_ENCODE_CTX ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	php_crypto_base64_decode_init(&ctx);
	out_len = PHP_CRYPTO_BASE64_DECODING_SIZE_REAL(in_len);
	out = (char *) emalloc(out_len);

	if (php_crypto_base64_decode_update(&ctx, out, &out_len, in, in_len TSRMLS_CC) < 0) {
		RETURN_FALSE;
	}
	php_crypto_base64_decode_finish(&ctx, out, &final_len);
	out_len += final_len;
	out[out_len] = 0;
	RETURN_STRINGL(out, out_len, 0);
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
   Encodes block of characters from $data and saves the reminder of the last block to the encoding context */
PHP_CRYPTO_METHOD(Base64, encodeUpdate)
{
	char *in, *out;
	int in_len, out_len, real_len;
	php_crypto_base64_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_base64_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	if (intern->status == PHP_CRYPTO_BASE64_STATUS_DECODE) {
		PHP_CRYPTO_THROW_BASE64_EXCEPTION(ENCODE_UPDATE_STATUS, "The object is already used for decoding");
		return;
	}
	if (intern->status == PHP_CRYPTO_BASE64_STATUS_CLEAR) {
		php_crypto_base64_encode_init(intern->ctx);
		intern->status = PHP_CRYPTO_BASE64_STATUS_ENCODE;
	}

	real_len = PHP_CRYPTO_BASE64_ENCODING_SIZE_REAL(in_len, intern->ctx);
	if (real_len < PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN) {
		char buff[PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN+1];
		php_crypto_base64_encode_update(intern->ctx, buff, &out_len, in, in_len);
		if (out_len == 0) {
			RETURN_EMPTY_STRING();
		}
		buff[out_len] = 0;
		RETURN_STRINGL(buff, out_len, 1);
	} else {
		out = (char *) emalloc(real_len+1);
		php_crypto_base64_encode_update(intern->ctx, out, &out_len, in, in_len);
		out[out_len] = 0;
		RETURN_STRINGL(out, out_len, 0);
	}
}

/* {{{ proto Crypto\Base64::encodeFinish()
   Encodes characters that left in the encoding context */
PHP_CRYPTO_METHOD(Base64, encodeFinish)
{
	char out[PHP_CRYPTO_BASE64_ENCODING_SIZE_MIN];
	int out_len;
	php_crypto_base64_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_base64_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	if (intern->status != PHP_CRYPTO_BASE64_STATUS_ENCODE) {
		PHP_CRYPTO_THROW_BASE64_EXCEPTION(ENCODE_FINISH_STATUS, "The object has not been intialized for encoding");
		return;
	}

	php_crypto_base64_encode_finish(intern->ctx, out, &out_len);
	if (out_len == 0) {
		RETURN_EMPTY_STRING();
	}
	out[out_len] = 0;
	RETURN_STRINGL(out, out_len, 1);
}

/* {{{ proto Crypto\Base64::decode(string $data)
   Decodes block of characters from $data and saves the reminder of the last block to the encoding context */
PHP_CRYPTO_METHOD(Base64, decodeUpdate)
{
	char *in, *out;
	int in_len, out_len, real_len;
	php_crypto_base64_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &in, &in_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_base64_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	if (intern->status == PHP_CRYPTO_BASE64_STATUS_ENCODE) {
		PHP_CRYPTO_THROW_BASE64_EXCEPTION(DECODE_UPDATE_STATUS, "The object is already used for encoding");
		return;
	}
	if (intern->status == PHP_CRYPTO_BASE64_STATUS_CLEAR) {
		php_crypto_base64_decode_init(intern->ctx);
		intern->status = PHP_CRYPTO_BASE64_STATUS_DECODE;
	}

	real_len = PHP_CRYPTO_BASE64_DECODING_SIZE_REAL(in_len);
	if (real_len < PHP_CRYPTO_BASE64_DECODING_SIZE_MIN) {
		char buff[PHP_CRYPTO_BASE64_DECODING_SIZE_MIN];
		if (php_crypto_base64_decode_update(intern->ctx, buff, &out_len, in, in_len TSRMLS_CC) < 0) {
			return;
		}
		if (out_len == 0) {
			RETURN_EMPTY_STRING();
		}
		buff[out_len] = 0;
		RETURN_STRINGL(buff, out_len, 1);
	} else {
		out = (char *) emalloc(real_len);
		if (php_crypto_base64_decode_update(intern->ctx, out, &out_len, in, in_len TSRMLS_CC) < 0) {
			efree(out);
			return;
		}
		out[out_len] = 0;
		RETURN_STRINGL(out, out_len, 0);
	}
}

/* {{{ proto Crypto\Base64::decodeFinish()
   Decodes characters that left in the encoding context */
PHP_CRYPTO_METHOD(Base64, decodeFinish)
{
	char out[PHP_CRYPTO_BASE64_DECODING_SIZE_MIN];
	int out_len;
	php_crypto_base64_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_base64_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	if (intern->status != PHP_CRYPTO_BASE64_STATUS_DECODE) {
		PHP_CRYPTO_THROW_BASE64_EXCEPTION(DECODE_FINISH_STATUS, "The object has not been intialized for decoding");
		return;
	}

	php_crypto_base64_decode_finish(intern->ctx, out, &out_len);
	if (out_len == 0) {
		RETURN_EMPTY_STRING();
	}
	out[out_len] = 0;
	RETURN_STRINGL(out, out_len, 1);
}
