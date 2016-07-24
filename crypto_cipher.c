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

#define PHPC_SMART_CSTR_INCLUDE 1

#include "php.h"
#include "php_crypto.h"
#include "php_crypto_cipher.h"
#include "php_crypto_object.h"
#include "zend_exceptions.h"
#include "ext/standard/php_string.h"

#include <openssl/evp.h>

/* ERRORS */

PHP_CRYPTO_EXCEPTION_DEFINE(Cipher)
PHP_CRYPTO_ERROR_INFO_BEGIN(Cipher)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	ALGORITHM_NOT_FOUND,
	"Cipher '%s' algorithm not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_NOT_FOUND,
	"Cipher static method '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_TOO_MANY_ARGS,
	"Cipher static method %s can accept max two arguments"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	MODE_NOT_FOUND,
	"Cipher mode not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	MODE_NOT_AVAILABLE,
	"Cipher mode %s is not available in installed OpenSSL library"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AUTHENTICATION_NOT_SUPPORTED,
	"The authentication is not supported for %s cipher mode"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	KEY_LENGTH_INVALID,
	"Invalid length of key for cipher '%s' algorithm "
	"(required length: %d)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	IV_LENGTH_INVALID,
	"Invalid length of initial vector for cipher '%s' algorithm "
	"(required length: %d)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_SETTER_FORBIDDEN,
	"AAD setter has to be called before encryption or decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_SETTER_FAILED,
	"AAD setter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_LENGTH_HIGH,
	"AAD length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_GETTER_FORBIDDEN,
	"Tag getter has to be called after encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_SETTER_FORBIDDEN,
	"Tag setter has to be called before decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_GETTER_FAILED,
	"Tag getter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_SETTER_FAILED,
	"Tag setter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_LENGTH_SETTER_FORBIDDEN,
	"Tag length setter has to be called before encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_LENGTH_LOW,
	"Tag length can't be lower than 32 bits (4 characters)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_LENGTH_HIGH,
	"Tag length can't exceed 128 bits (16 characters)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_VERIFY_FAILED,
	"Tag verifycation failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_ALG_FAILED,
	"Initialization of cipher algorithm failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_CTX_FAILED,
	"Initialization of cipher context failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_ENCRYPT_FORBIDDEN,
	"Cipher object is already used for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_DECRYPT_FORBIDDEN,
	"Cipher object is already used for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_FAILED,
	"Updating of cipher failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_ENCRYPT_FORBIDDEN,
	"Cipher object is not initialized for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_DECRYPT_FORBIDDEN,
	"Cipher object is not initialized for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_FAILED,
	"Finalizing of cipher failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_ENCRYPT_FORBIDDEN,
	"Cipher object is not initialized for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_DECRYPT_FORBIDDEN,
	"Cipher object is not initialized for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INPUT_DATA_LENGTH_HIGH,
	"Input data length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_END()


/* ARG INFOS */

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_list, 0, 0, 0)
ZEND_ARG_INFO(0, aliases)
ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_static, 0)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, arguments)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_construct, 0, 0, 1)
ZEND_ARG_INFO(0, algorithm)
ZEND_ARG_INFO(0, mode)
ZEND_ARG_INFO(0, key_size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_init, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_mode, 0)
ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_set_tag_len, 0)
ZEND_ARG_INFO(0, tag_length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_set_tag, 0)
ZEND_ARG_INFO(0, tag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_set_aad, 0)
ZEND_ARG_INFO(0, aad)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_crypt, 0, 0, 2)
ZEND_ARG_INFO(0, data)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()


static const zend_function_entry php_crypto_cipher_object_methods[] = {
	PHP_CRYPTO_ME(
		Cipher, getAlgorithms,
		arginfo_crypto_cipher_list,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, hasAlgorithm,
		arginfo_crypto_cipher_algorithm,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, hasMode,
		arginfo_crypto_cipher_mode,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, __callStatic,
		arginfo_crypto_cipher_static,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, __construct,
		arginfo_crypto_cipher_construct,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getAlgorithmName,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptInit,
		arginfo_crypto_cipher_init,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptUpdate,
		arginfo_crypto_cipher_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encrypt,
		arginfo_crypto_cipher_crypt,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptInit,
		arginfo_crypto_cipher_init,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptUpdate,
		arginfo_crypto_cipher_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decrypt,
		arginfo_crypto_cipher_crypt,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getBlockSize,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getKeyLength,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getIVLength,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getMode,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getTag,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, setTag,
		arginfo_crypto_cipher_set_tag,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, setTagLength,
		arginfo_crypto_cipher_set_tag_len,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, setAAD,
		arginfo_crypto_cipher_set_aad,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

/* cipher modes lookup table */
static const php_crypto_cipher_mode php_crypto_cipher_modes[] = {
	PHP_CRYPTO_CIPHER_MODE_ENTRY(ECB)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CBC)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CFB)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(OFB)
#ifdef EVP_CIPH_CTR_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CTR)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(CTR)
#endif
#ifdef EVP_CIPH_GCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(GCM, 1, 0,
			EVP_CTRL_GCM_SET_IVLEN,
			EVP_CTRL_GCM_SET_TAG, EVP_CTRL_GCM_GET_TAG)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(GCM)
#endif
#ifdef EVP_CIPH_CCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(CCM, 1, 1,
			EVP_CTRL_CCM_SET_IVLEN,
			EVP_CTRL_CCM_SET_TAG, EVP_CTRL_CCM_GET_TAG)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(CCM)
#endif
#ifdef EVP_CIPH_XTS_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(XTS)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(XTS)
#endif
	PHP_CRYPTO_CIPHER_MODE_ENTRY_END
};

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_cipher);

/* algorithm name getter macros */
#define PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME_EX(this_object) \
	PHPC_READ_PROPERTY(php_crypto_cipher_ce, this_object, \
		"algorithm", sizeof("algorithm")-1, 1)

#define PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME(this_object) \
	Z_STRVAL_P(PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME_EX(this_object))


/* {{{ crypto_cipher free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_cipher)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_cipher);

	EVP_CIPHER_CTX_free(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));

	if (PHP_CRYPTO_CIPHER_AAD(PHPC_THIS)) {
		efree(PHP_CRYPTO_CIPHER_AAD(PHPC_THIS));
	}
	if (PHP_CRYPTO_CIPHER_TAG(PHPC_THIS)) {
		efree(PHP_CRYPTO_CIPHER_TAG(PHPC_THIS));
	}

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_cipher create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_cipher)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_cipher);

	PHP_CRYPTO_CIPHER_CTX(PHPC_THIS) = EVP_CIPHER_CTX_new();
	if (!PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)) {
		php_error(E_ERROR, "Creating Cipher object failed");
	}

	PHP_CRYPTO_CIPHER_AAD(PHPC_THIS) = NULL;
	PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) = 0;
	PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) = NULL;
	/* this is a default len for the tag */
	PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) =
			PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_DEFAULT;

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(crypto_cipher);
}
/* }}} */

/* {{{ crypto_cipher create object handler */
PHPC_OBJ_HANDLER_CREATE(crypto_cipher)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(crypto_cipher);
}
/* }}} */

/* {{{ crypto_cipher clone object handler */
PHPC_OBJ_HANDLER_CLONE(crypto_cipher)
{
	zend_bool copy_success;
	PHPC_OBJ_HANDLER_CLONE_INIT(crypto_cipher);

	PHPC_THAT->status = PHPC_THIS->status;
	if (PHP_CRYPTO_CIPHER_TAG(PHPC_THIS)) {
		PHP_CRYPTO_CIPHER_TAG(PHPC_THAT) = emalloc(
				PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS));
		memcpy(PHP_CRYPTO_CIPHER_TAG(PHPC_THAT),
				PHP_CRYPTO_CIPHER_TAG(PHPC_THIS),
				PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS));
		PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THAT) =
				PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS);
	}
	if (PHP_CRYPTO_CIPHER_AAD(PHPC_THIS)) {
		PHP_CRYPTO_CIPHER_AAD(PHPC_THIS) = emalloc(
				PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS));
		memcpy(PHP_CRYPTO_CIPHER_AAD(PHPC_THAT),
				PHP_CRYPTO_CIPHER_AAD(PHPC_THIS),
				PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS));
		PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THAT) =
				PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS);
	}

#ifdef PHP_CRYPTO_HAS_CIPHER_CTX_COPY
	copy_success = EVP_CIPHER_CTX_copy(
			PHP_CRYPTO_CIPHER_CTX(PHPC_THAT),
			PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));
#else
	memcpy(PHP_CRYPTO_CIPHER_CTX(PHPC_THAT),
			PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			sizeof *(PHP_CRYPTO_CIPHER_CTX(PHPC_THAT)));

	copy_success = 1;
	if (PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher_data &&
			PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher->ctx_size) {
		PHP_CRYPTO_CIPHER_CTX(PHPC_THAT)->cipher_data = OPENSSL_malloc(
				PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher->ctx_size);
		if (!PHP_CRYPTO_CIPHER_CTX(PHPC_THAT)->cipher_data) {
			copy_success = 0;
		}
		memcpy(PHP_CRYPTO_CIPHER_CTX(PHPC_THAT)->cipher_data,
				PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher_data,
				PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher->ctx_size);
	}
#endif

	PHP_CRYPTO_CIPHER_ALG(PHPC_THAT) = EVP_CIPHER_CTX_cipher(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));

	if (!copy_success) {
		php_error(E_ERROR, "Cloning of Cipher object failed");
	}

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_cipher)
{
	zend_class_entry ce;
	const php_crypto_cipher_mode *mode;

	/* CipherException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, Cipher);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Cipher);

	/* Cipher class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Cipher), php_crypto_cipher_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, crypto_cipher);
	php_crypto_cipher_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(crypto_cipher);
	PHPC_OBJ_SET_HANDLER_OFFSET(crypto_cipher);
	PHPC_OBJ_SET_HANDLER_FREE(crypto_cipher);
	PHPC_OBJ_SET_HANDLER_CLONE(crypto_cipher);
	zend_declare_property_null(php_crypto_cipher_ce,
			"algorithm", sizeof("algorithm")-1, ZEND_ACC_PROTECTED TSRMLS_CC);

	/* Cipher constants for modes */
	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		zend_declare_class_constant_long(php_crypto_cipher_ce,
				mode->constant, strlen(mode->constant), mode->value TSRMLS_CC);
	}

	return SUCCESS;
}
/* }}} */

/* METHODS */

/* {{{ php_crypto_get_algorithm_object_ex */
static inline void php_crypto_cipher_set_algorithm_name(zval *object,
		char *algorithm, phpc_str_size_t algorithm_len TSRMLS_DC)
{
	php_strtoupper(algorithm, algorithm_len);
	zend_update_property_stringl(php_crypto_cipher_ce, object,
			"algorithm", sizeof("algorithm")-1, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_get_cipher_algorithm */
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm(
		char *algorithm, phpc_str_size_t algorithm_len)
{
	const EVP_CIPHER *cipher;

	if (algorithm_len > PHP_CRYPTO_CIPHER_ALGORITHM_LEN_MAX) {
		return NULL;
	}

	php_strtoupper(algorithm, algorithm_len);
	cipher = EVP_get_cipherbyname(algorithm);
	if (!cipher) {
		php_strtolower(algorithm, algorithm_len);
		cipher = EVP_get_cipherbyname(algorithm);
	}
	return cipher;
}
/* }}} */

/* {{{ php_crypto_get_cipher_algorithm_from_params_ex */
static const EVP_CIPHER *php_crypto_get_cipher_algorithm_from_params_ex(
		zval *object, char *algorithm, phpc_str_size_t algorithm_len, zval *pz_mode,
		zval *pz_key_size, zend_bool is_static TSRMLS_DC)
{
	const EVP_CIPHER *cipher;
	phpc_smart_cstr alg_buf = {0};

	/* if mode is not set, then it is already contained in the algorithm string */
	if (!pz_mode || Z_TYPE_P(pz_mode) == IS_NULL) {
		cipher = php_crypto_get_cipher_algorithm(algorithm, algorithm_len);
		if (!cipher) {
			if (is_static) {
				php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, STATIC_METHOD_NOT_FOUND),
						algorithm);
			} else {
				php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, ALGORITHM_NOT_FOUND),
						algorithm);
			}
		} else if (object) {
			php_crypto_cipher_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
		}
		return cipher;
	}

	phpc_smart_cstr_appendl(&alg_buf, algorithm, algorithm_len);
	phpc_smart_cstr_appendc(&alg_buf, '-');

	/* copy key size if available */
	if (pz_key_size && Z_TYPE_P(pz_key_size) != IS_NULL) {
		if (Z_TYPE_P(pz_key_size) == IS_STRING) {
			phpc_smart_cstr_appendl(&alg_buf, Z_STRVAL_P(pz_key_size), Z_STRLEN_P(pz_key_size));
		} else {
			zval z_key_size = *pz_key_size;
			zval_copy_ctor(&z_key_size);
			convert_to_string(&z_key_size);
			phpc_smart_cstr_appendl(&alg_buf, Z_STRVAL(z_key_size), Z_STRLEN(z_key_size));
			phpc_smart_cstr_appendc(&alg_buf, '-');
			zval_dtor(&z_key_size);
		}
	}

	/* copy mode */
	if (Z_TYPE_P(pz_mode) == IS_LONG) {
		const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode_ex(Z_LVAL_P(pz_mode));
		if (!mode) {
			php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, MODE_NOT_FOUND));
			phpc_smart_cstr_free(&alg_buf);
			return NULL;
		}
		if (mode->value == PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED) {
			php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, MODE_NOT_AVAILABLE), mode->name);
			phpc_smart_cstr_free(&alg_buf);
			return NULL;
		}
		phpc_smart_cstr_appendl(&alg_buf, mode->name, PHP_CRYPTO_CIPHER_MODE_LEN);
	} else if (Z_TYPE_P(pz_mode) == IS_STRING) {
		phpc_smart_cstr_appendl(&alg_buf, Z_STRVAL_P(pz_mode), Z_STRLEN_P(pz_mode));
	} else {
		zval z_mode = *pz_mode;
		zval_copy_ctor(&z_mode);
		convert_to_string(&z_mode);
		phpc_smart_cstr_appendl(&alg_buf, Z_STRVAL(z_mode), Z_STRLEN(z_mode));
		zval_dtor(&z_mode);
	}

	phpc_smart_cstr_0(&alg_buf);
	cipher = php_crypto_get_cipher_algorithm(alg_buf.c, alg_buf.len);
	if (!cipher) {
		if (is_static) {
			php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, STATIC_METHOD_NOT_FOUND), alg_buf.c);
		} else {
			php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, ALGORITHM_NOT_FOUND), alg_buf.c);
		}
	} else if (object) {
		php_crypto_cipher_set_algorithm_name(object, alg_buf.c, alg_buf.len TSRMLS_CC);
	}
	phpc_smart_cstr_free(&alg_buf);
	return cipher;
}
/* }}} */

/* {{{ php_crypto_get_cipher_algorithm_from_params */
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm_from_params(
		char *algorithm, phpc_str_size_t algorithm_len, zval *pz_mode, zval *pz_key_size TSRMLS_DC)
{
	return php_crypto_get_cipher_algorithm_from_params_ex(
			NULL, algorithm, algorithm_len, pz_mode, pz_key_size, 0 TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_ex */
static int php_crypto_set_cipher_algorithm_ex(PHPC_THIS_DECLARE(crypto_cipher),
		char *algorithm, phpc_str_size_t algorithm_len TSRMLS_DC)
{
	const EVP_CIPHER *cipher = php_crypto_get_cipher_algorithm(algorithm, algorithm_len);
	if (!cipher) {
		return FAILURE;
	}
	PHP_CRYPTO_CIPHER_ALG(PHPC_THIS) = cipher;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm */
static int php_crypto_set_cipher_algorithm(zval *object,
		char *algorithm, phpc_str_size_t algorithm_len TSRMLS_DC)
{
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_cipher, object);
	php_crypto_cipher_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
	return php_crypto_set_cipher_algorithm_ex(PHPC_THIS, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_from_params_ex */
static int php_crypto_set_cipher_algorithm_from_params_ex(
		zval *object, char *algorithm, phpc_str_size_t algorithm_len,
		zval *pz_mode, zval *pz_key_size, zend_bool is_static TSRMLS_DC)
{
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_cipher, object);
	const EVP_CIPHER *cipher = php_crypto_get_cipher_algorithm_from_params_ex(
			object, algorithm, algorithm_len, pz_mode, pz_key_size, is_static TSRMLS_CC);

	if (!cipher) {
		return FAILURE;
	}

	PHP_CRYPTO_CIPHER_ALG(PHPC_THIS) = cipher;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_from_params */
static int php_crypto_set_cipher_algorithm_from_params(
		zval *object, char *algorithm, phpc_str_size_t algorithm_len,
		zval *pz_mode, zval *pz_key_size TSRMLS_DC)
{
	return php_crypto_set_cipher_algorithm_from_params_ex(
			object, algorithm, algorithm_len, pz_mode, pz_key_size, 0 TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_get_cipher_mode_ex */
PHP_CRYPTO_API const php_crypto_cipher_mode *php_crypto_get_cipher_mode_ex(long mode_value)
{
	const php_crypto_cipher_mode *mode;

	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		if (mode_value == mode->value) {
			return mode;
		}
	}
	return NULL;
}
/* }}} */

/* {{{ php_crypto_get_cipher_mode_ex */
PHP_CRYPTO_API const php_crypto_cipher_mode *php_crypto_get_cipher_mode(const EVP_CIPHER *cipher)
{
	return php_crypto_get_cipher_mode_ex(EVP_CIPHER_mode(cipher));
}
/* }}} */

/* {{{ php_crypto_cipher_is_mode_authenticated_ex */
static int php_crypto_cipher_is_mode_authenticated_ex(const php_crypto_cipher_mode *mode TSRMLS_DC)
{
	if (!mode) { /* this should never happen */
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, MODE_NOT_FOUND));
		return FAILURE;
	}
	if (!mode->auth_enc) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, AUTHENTICATION_NOT_SUPPORTED),
				mode->name);
		return FAILURE;
	}
	return SUCCESS;
}

/* {{{ php_crypto_cipher_is_mode_authenticated */
static int php_crypto_cipher_is_mode_authenticated(PHPC_THIS_DECLARE(crypto_cipher) TSRMLS_DC)
{
	return php_crypto_cipher_is_mode_authenticated_ex(
			php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS)) TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_cipher_set_tag */
PHP_CRYPTO_API int php_crypto_cipher_set_tag(EVP_CIPHER_CTX *cipher_ctx,
		const php_crypto_cipher_mode *mode, unsigned char *tag, int tag_len TSRMLS_DC)
{
	if (!tag) {
		return SUCCESS;
	}
	if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->auth_set_tag_flag, tag_len, tag)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_SETTER_FAILED));
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_tag_len */
static int php_crypto_cipher_check_tag_len(int tag_len TSRMLS_DC)
{
	if (tag_len < PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MIN) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_LENGTH_LOW));
		return FAILURE;
	}
	if (tag_len > PHP_CRYPTO_CIPHER_AUTH_TAG_LENGTH_MAX) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_LENGTH_HIGH));
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_key_len */
static int php_crypto_cipher_check_key_len(zval *zobject, PHPC_THIS_DECLARE(crypto_cipher),
		phpc_str_size_t key_len TSRMLS_DC)
{
	int int_key_len, alg_key_len = EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	PHPC_READ_PROPERTY_RV_DECLARE;

	if (php_crypto_str_size_to_int(key_len, &int_key_len) == SUCCESS &&
			int_key_len != alg_key_len &&
			!EVP_CIPHER_CTX_set_key_length(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), int_key_len)) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, KEY_LENGTH_INVALID),
				PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_iv_len */
static int php_crypto_cipher_check_iv_len(zval *zobject, PHPC_THIS_DECLARE(crypto_cipher),
		const php_crypto_cipher_mode *mode, phpc_str_size_t iv_len TSRMLS_DC)
{
	int int_iv_len, alg_iv_len = EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	PHPC_READ_PROPERTY_RV_DECLARE;

	if (php_crypto_str_size_to_int(iv_len, &int_iv_len) == FAILURE) {
		return FAILURE;
	}

	if (int_iv_len == alg_iv_len) {
		return SUCCESS;
	}

	if (!mode->auth_enc || int_iv_len == INT_MAX ||
			!EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
				mode->auth_ivlen_flag, int_iv_len, NULL)) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, IV_LENGTH_INVALID),
				PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME(zobject), alg_iv_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_init_ex */
static PHPC_OBJ_STRUCT_NAME(crypto_cipher) *php_crypto_cipher_init_ex(
		zval *zobject, char *key, phpc_str_size_t key_len,
		char *iv, phpc_str_size_t iv_len, int enc TSRMLS_DC)
{
	const php_crypto_cipher_mode *mode;
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_cipher, zobject);

	/* check algorithm status */
	if (enc && PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INIT_ENCRYPT_FORBIDDEN));
		return NULL;
	} else if (!enc && PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INIT_DECRYPT_FORBIDDEN));
		return NULL;
	}

	/* initialize encryption/decryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), PHP_CRYPTO_CIPHER_ALG(PHPC_THIS),
			NULL, NULL, NULL, enc)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INIT_ALG_FAILED));
		return NULL;
	}

	/* check key length */
	if (php_crypto_cipher_check_key_len(zobject, PHPC_THIS, key_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* get mode */
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	/* mode with inlen init requires also pre-setting tag length */
	if (mode->auth_inlen_init && enc) {
		EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), mode->auth_set_tag_flag,
				PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS), NULL);
	}

	/* check initialization vector length */
	if (php_crypto_cipher_check_iv_len(zobject, PHPC_THIS, mode, iv_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	if (mode->auth_enc && !enc &&
			php_crypto_cipher_set_tag(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), mode,
				PHP_CRYPTO_CIPHER_TAG(PHPC_THIS),
				PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) ? PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) : 0
				TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* initialize encryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), NULL, NULL,
			(unsigned char *) key, (unsigned char *) iv, enc)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INIT_CTX_FAILED));
		return NULL;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(PHPC_THIS, enc, INIT);


	return PHPC_THIS;
}
/* }}} */

/* {{{ php_crypto_cipher_init */
static inline void php_crypto_cipher_init(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	char *key, *iv = NULL;
	phpc_str_size_t key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s",
			&key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	if (php_crypto_cipher_init_ex(getThis(), key, key_len, iv, iv_len, enc TSRMLS_CC)) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ php_crypto_cipher_write_aad */
PHP_CRYPTO_API int php_crypto_cipher_write_aad(
		EVP_CIPHER_CTX *cipher_ctx, unsigned char *aad, int aad_len TSRMLS_DC)
{
	int outlen, ret;

	if (aad) {
		ret = EVP_CipherUpdate(cipher_ctx, NULL, &outlen, aad, aad_len);
	} else {
		unsigned char buf[4];
		ret = EVP_CipherUpdate(cipher_ctx, NULL, &outlen, buf, 0);
	}

	if (!ret) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, AAD_SETTER_FAILED));
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_write_inlen */
static int php_crypto_cipher_write_inlen(
		EVP_CIPHER_CTX *cipher_ctx, int inlen TSRMLS_DC)
{
	int outlen;

	if (!EVP_CipherUpdate(cipher_ctx, NULL, &outlen, NULL, inlen)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_FAILED));
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_auth_init */
static int php_crypto_cipher_auth_init(
		PHPC_THIS_DECLARE(crypto_cipher), int inlen TSRMLS_DC)
{
	EVP_CIPHER_CTX *cipher_ctx = PHP_CRYPTO_CIPHER_CTX(PHPC_THIS);
	const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode_ex(
				PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	/* auth init is just for auth modes */
	if (!mode->auth_enc) {
		return SUCCESS;
	}

	/* check if plain text length needs to be initialized (CCM mode) */
	if (mode->auth_inlen_init && php_crypto_cipher_write_inlen(
			cipher_ctx, inlen TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	/* write additional authenticated data */
	if (php_crypto_cipher_write_aad(
			cipher_ctx,
			PHP_CRYPTO_CIPHER_AAD(PHPC_THIS),
			PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_update */
static inline void php_crypto_cipher_update(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	PHPC_STR_DECLARE(out);
	char *data;
	phpc_str_size_t data_str_size;
	int out_len, update_len, data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_str_size) == FAILURE) {
		return;
	}

	if (php_crypto_str_size_to_int(data_str_size, &data_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INPUT_DATA_LENGTH_HIGH));
		RETURN_FALSE;
	}

	PHPC_THIS_FETCH(crypto_cipher);

	/* check algorithm status */
	if (enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_ENCRYPT_FORBIDDEN));
		RETURN_FALSE;
	} else if (!enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_DECRYPT_FORBIDDEN));
		RETURN_FALSE;
	}

	/* if the crypto is in init state (first update), then do auth init */
	if (PHP_CRYPTO_CIPHER_IS_IN_INIT_STATE(PHPC_THIS) &&
			php_crypto_cipher_auth_init(PHPC_THIS, data_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	out_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	update_len = out_len;
	PHPC_STR_ALLOC(out, out_len);

	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &update_len,
			(unsigned char *) data, data_len)) {
		/* get mode info */
		const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode_ex(
					PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

		if (!enc && mode->auth_inlen_init) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_VERIFY_FAILED));
		} else {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_FAILED));
		}
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(PHPC_THIS, enc, UPDATE);
	if (out_len > update_len) {
		PHPC_STR_REALLOC(out, update_len);
	}
	PHPC_STR_VAL(out)[update_len] = 0;
	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ php_crypto_cipher_finish */
static inline void php_crypto_cipher_finish(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	PHPC_STR_DECLARE(out);
	const php_crypto_cipher_mode *mode;
	int out_len, final_len = 0;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);

	/* check algorithm status */
	if (enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_ENCRYPT_FORBIDDEN));
		RETURN_FALSE;
	} else if (!enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_DECRYPT_FORBIDDEN));
		RETURN_FALSE;
	}

	out_len = EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	PHPC_STR_ALLOC(out, out_len);

	/* get mode info */
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	/* finalize cipher context */
	if ((enc || !mode->auth_inlen_init) && !EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &final_len)) {
		if (!enc && mode->auth_enc) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_VERIFY_FAILED));
		} else {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_FAILED));
		}
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(PHPC_THIS, enc, FINAL);
	if (out_len > final_len) {
		PHPC_STR_REALLOC(out, final_len);
	}
	PHPC_STR_VAL(out)[final_len] = 0;
	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ php_crypto_cipher_crypt */
static inline void php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	PHPC_STR_DECLARE(out);
	const php_crypto_cipher_mode *mode;
	char *data, *key, *iv = NULL;
	phpc_str_size_t data_str_size, key_len, iv_len = 0;
	int data_len, update_len, out_len, final_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s",
			&data, &data_str_size, &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	if (php_crypto_str_size_to_int(data_str_size, &data_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INPUT_DATA_LENGTH_HIGH));
		RETURN_FALSE;
	}

	PHPC_THIS = php_crypto_cipher_init_ex(getThis(), key, key_len, iv, iv_len, enc TSRMLS_CC);
	if (PHPC_THIS == NULL) {
		RETURN_FALSE;
	}

	/* do auth init */
	if (php_crypto_cipher_auth_init(PHPC_THIS, data_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	out_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	PHPC_STR_ALLOC(out, out_len);

	/* get mode info */
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &update_len,
			(unsigned char *) data, data_len)) {
		if (!enc && mode->auth_inlen_init) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_VERIFY_FAILED));
		} else {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_FAILED));
		}
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}

	/* finalize cipher context */
	if ((enc || !mode->auth_inlen_init) && !EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) (PHPC_STR_VAL(out) + update_len), &final_len)) {
		if (!enc && mode->auth_enc) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_VERIFY_FAILED));
		} else {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_FAILED));
		}
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(PHPC_THIS, enc, FINAL);

	final_len += update_len;
	if (out_len > final_len) {
		PHPC_STR_REALLOC(out, final_len);
	}
	PHPC_STR_VAL(out)[final_len] = 0;
	PHPC_STR_RETURN(out);
}
/* }}} */

/* {{{ proto static string Crypto\Cipher::getAlgorithms(bool $aliases = false,
			string $prefix = null)
	Returns cipher algorithms */
PHP_CRYPTO_METHOD(Cipher, getAlgorithms)
{
	php_crypto_object_fn_get_names(INTERNAL_FUNCTION_PARAM_PASSTHRU,
			OBJ_NAME_TYPE_CIPHER_METH);
}
/* }}} */

/* {{{ proto static bool Crypto\Cipher::hasAlgorithm(string $algorithm)
	Finds out whether algorithm exists */
PHP_CRYPTO_METHOD(Cipher, hasAlgorithm)
{
	char *algorithm;
	phpc_str_size_t algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	if (php_crypto_get_cipher_algorithm(algorithm, algorithm_len)) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto static bool Crypto\Cipher::hasMode(int $mode)
	Finds out whether the cipher mode is defined in the used OpenSSL library */
PHP_CRYPTO_METHOD(Cipher, hasMode)
{
	phpc_long_t mode;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &mode) == FAILURE) {
		return;
	}

	RETURN_BOOL(mode != PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED && (mode & EVP_CIPH_MODE));
}
/* }}} */

/* {{{ proto static Crypto\Cipher::__callStatic(string $name, array $arguments)
	Cipher magic method for calling static methods */
PHP_CRYPTO_METHOD(Cipher, __callStatic)
{
	char *algorithm;
	int argc;
	phpc_str_size_t algorithm_len;
	phpc_val *ppv_mode;
	zval *pz_mode, *pz_key_size, *args;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa",
			&algorithm, &algorithm_len, &args) == FAILURE) {
		return;
	}

	argc = PHPC_HASH_NUM_ELEMENTS(Z_ARRVAL_P(args));
	if (argc > 2) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, STATIC_METHOD_TOO_MANY_ARGS), algorithm);
		return;
	}

	object_init_ex(return_value, php_crypto_cipher_ce);

	if (argc == 0) {
		if (php_crypto_set_cipher_algorithm(
				return_value, algorithm, algorithm_len TSRMLS_CC) == FAILURE) {
			php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, STATIC_METHOD_NOT_FOUND), algorithm);
		}
		return;
	}

	PHPC_HASH_INTERNAL_POINTER_RESET(Z_ARRVAL_P(args));
	PHPC_HASH_GET_CURRENT_DATA(Z_ARRVAL_P(args), ppv_mode);
	PHPC_PVAL_TO_PZVAL(ppv_mode, pz_mode);
	if (argc == 1) {
		pz_key_size = NULL;
	} else {
		phpc_val *ppv_key_size;
		PHPC_HASH_MOVE_FORWARD(Z_ARRVAL_P(args));
		PHPC_HASH_GET_CURRENT_DATA(Z_ARRVAL_P(args), ppv_key_size);
		PHPC_PVAL_TO_PZVAL(ppv_key_size, pz_key_size);
	}
	php_crypto_set_cipher_algorithm_from_params_ex(
			return_value, algorithm, algorithm_len, pz_mode, pz_key_size, 1 TSRMLS_CC);
}
/* }}} */

/* {{{ proto Crypto\Cipher::__construct(string $algorithm, int $mode = NULL, string $key_size = NULL)
	Cipher constructor */
PHP_CRYPTO_METHOD(Cipher, __construct)
{
	char *algorithm, *algorithm_uc;
	phpc_str_size_t algorithm_len;
	zval *mode = NULL, *key_size = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zz",
			&algorithm, &algorithm_len, &mode, &key_size) == FAILURE) {
		return;
	}

	algorithm_uc = estrdup(algorithm);
	php_crypto_set_cipher_algorithm_from_params(
			getThis(), algorithm_uc, strlen(algorithm_uc), mode, key_size TSRMLS_CC);
	efree(algorithm_uc);
}
/* }}} */

/* {{{ proto string Crypto\Cipher::getAlgorithmName()
	Returns cipher algorithm string */
PHP_CRYPTO_METHOD(Cipher, getAlgorithmName)
{
	zval *algorithm;
	PHPC_READ_PROPERTY_RV_DECLARE;

	algorithm = PHP_CRYPTO_CIPHER_GET_ALGORITHM_NAME_EX(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
}
/* }}} */

/* {{{ proto bool Crypto\Cipher::encryptInit(string $key, string $iv = null)
	Initializes cipher encryption */
PHP_CRYPTO_METHOD(Cipher, encryptInit)
{
	php_crypto_cipher_init(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/* {{{ proto string Crypto\Cipher::encryptUpdate(string $data)
	Updates cipher encryption */
PHP_CRYPTO_METHOD(Cipher, encryptUpdate)
{
	php_crypto_cipher_update(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/* {{{ proto string Crypto\Cipher::encryptFinish()
	Finalizes cipher encryption */
PHP_CRYPTO_METHOD(Cipher, encryptFinish)
{
	php_crypto_cipher_finish(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/* {{{ proto string Crypto\Cipher::encrypt(string $data, string $key, string $iv = null)
	Encrypts text to ciphertext */
PHP_CRYPTO_METHOD(Cipher, encrypt)
{
	php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/* {{{ proto void Crypto\Cipher::decryptInit(string $key, string $iv = null)
	Initializes cipher decryption */
PHP_CRYPTO_METHOD(Cipher, decryptInit)
{
	php_crypto_cipher_init(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

/* {{{ proto string Crypto\Cipher::decryptUpdate(string $data)
	Updates cipher decryption */
PHP_CRYPTO_METHOD(Cipher, decryptUpdate)
{
	php_crypto_cipher_update(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

/* {{{ proto string Crypto\Cipher::decryptFinish()
	Finalizes cipher decryption */
PHP_CRYPTO_METHOD(Cipher, decryptFinish)
{
	php_crypto_cipher_finish(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

/* {{{ proto string Crypto\Cipher::decrypt(string $data, string $key, string $iv = null)
	Decrypts ciphertext to decrypted text */
PHP_CRYPTO_METHOD(Cipher, decrypt)
{
	php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

/* {{{ proto int Crypto\Cipher::getBlockSize()
	Returns cipher block size */
PHP_CRYPTO_METHOD(Cipher, getBlockSize)
{
	PHPC_THIS_DECLARE(crypto_cipher);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	RETURN_LONG(EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getKeyLength()
	Returns cipher key length */
PHP_CRYPTO_METHOD(Cipher, getKeyLength)
{
	PHPC_THIS_DECLARE(crypto_cipher);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	RETURN_LONG(EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getIVLength()
	Returns cipher IV length */
PHP_CRYPTO_METHOD(Cipher, getIVLength)
{
	PHPC_THIS_DECLARE(crypto_cipher);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	RETURN_LONG(EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getMode()
	Returns cipher mode */
PHP_CRYPTO_METHOD(Cipher, getMode)
{
	PHPC_THIS_DECLARE(crypto_cipher);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	RETURN_LONG(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
}
/* }}} */

/* {{{ proto string Crypto\Cipher::getTag()
	Returns authentication tag */
PHP_CRYPTO_METHOD(Cipher, getTag)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	const php_crypto_cipher_mode *mode;
	PHPC_STR_DECLARE(tag);
	int tag_len;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status != PHP_CRYPTO_CIPHER_STATUS_ENCRYPT_FINAL) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_GETTER_FORBIDDEN));
		RETURN_FALSE;
	}

	tag_len = PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS);
	PHPC_STR_ALLOC(tag, tag_len);
	PHPC_STR_VAL(tag)[tag_len] = 0;

	if (!EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			mode->auth_get_tag_flag, tag_len, PHPC_STR_VAL(tag))) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_GETTER_FAILED));
		RETURN_FALSE;
	}

	PHPC_STR_RETURN(tag);
}
/* }}} */

/* {{{ proto bool Crypto\Cipher::setTag(string $tag)
	Sets authentication tag */
PHP_CRYPTO_METHOD(Cipher, setTag)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	const php_crypto_cipher_mode *mode;
	char *tag;
	phpc_str_size_t tag_str_size;
	int tag_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &tag, &tag_str_size) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE ||
			php_crypto_str_size_to_int(tag_str_size, &tag_len) == FAILURE ||
			php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status == PHP_CRYPTO_CIPHER_STATUS_CLEAR) {
		if (!PHP_CRYPTO_CIPHER_TAG(PHPC_THIS)) {
			PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) = emalloc(tag_len + 1);
		} else if (PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) < tag_len) {
			PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) = erealloc(
					PHP_CRYPTO_CIPHER_TAG(PHPC_THIS), tag_len + 1);
		}
		memcpy(PHP_CRYPTO_CIPHER_TAG(PHPC_THIS), tag, tag_len + 1);
		PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) = tag_len;
	} else if (PHPC_THIS->status == PHP_CRYPTO_CIPHER_STATUS_DECRYPT_INIT) {
		php_crypto_cipher_set_tag(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), mode,
				(unsigned char *) tag, tag_len TSRMLS_CC);
	} else {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_SETTER_FORBIDDEN));
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool Crypto\Cipher::setTagLength(int $tag_length)
	Set authentication tag length */
PHP_CRYPTO_METHOD(Cipher, setTagLength)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	const php_crypto_cipher_mode *mode;
	phpc_long_t tag_len_long;
	int tag_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &tag_len_long) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE ||
			PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) ||
			php_crypto_long_to_int(tag_len_long, &tag_len) == FAILURE ||
			php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status != PHP_CRYPTO_CIPHER_STATUS_ENCRYPT_INIT &&
			PHPC_THIS->status != PHP_CRYPTO_CIPHER_STATUS_CLEAR) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_LENGTH_SETTER_FORBIDDEN));
		RETURN_FALSE;
	}

	PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) = tag_len;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool Crypto\Cipher::setAAD(string $aad)
	Sets additional application data for authenticated encryption */
PHP_CRYPTO_METHOD(Cipher, setAAD)
{
	PHPC_THIS_DECLARE(crypto_cipher);
	char *aad;
	phpc_str_size_t aad_str_size;
	int aad_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &aad, &aad_str_size) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_cipher);
	if (php_crypto_cipher_is_mode_authenticated(PHPC_THIS TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (php_crypto_str_size_to_int(aad_str_size, &aad_len) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, AAD_LENGTH_HIGH));
		RETURN_FALSE;
	} else if (PHPC_THIS->status == PHP_CRYPTO_CIPHER_STATUS_CLEAR ||
			PHPC_THIS->status == PHP_CRYPTO_CIPHER_STATUS_ENCRYPT_INIT ||
			PHPC_THIS->status == PHP_CRYPTO_CIPHER_STATUS_DECRYPT_INIT) {
		if (!PHP_CRYPTO_CIPHER_AAD(PHPC_THIS)) {
			PHP_CRYPTO_CIPHER_AAD(PHPC_THIS) = emalloc(aad_len + 1);
		} else if (PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) < aad_len) {
			PHP_CRYPTO_CIPHER_AAD(PHPC_THIS) = erealloc(
					PHP_CRYPTO_CIPHER_AAD(PHPC_THIS), aad_len + 1);
		}
		memcpy(PHP_CRYPTO_CIPHER_AAD(PHPC_THIS), aad, aad_len + 1);
		PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) = aad_len;
	} else {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, AAD_SETTER_FORBIDDEN));
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */
