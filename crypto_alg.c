/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 Jakub Zelenka                                |
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
#include "php_crypto_alg.h"
#include "zend_exceptions.h"
#include "ext/standard/php_string.h"

#include <openssl/evp.h>

PHP_CRYPTO_EXCEPTION_DEFINE(Algorithm)

PHP_CRYPTO_EXCEPTION_DEFINE(Cipher)
PHP_CRYPTO_ERROR_INFO_BEGIN(Cipher)
PHP_CRYPTO_ERROR_INFO_ENTRY(ALGORITHM_NOT_FOUND, "Cipher '%s' algorithm not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_NOT_FOUND, "Cipher static method '%s' not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_TOO_MANY_ARGS, "Cipher static method %s can accept max two arguments")
PHP_CRYPTO_ERROR_INFO_ENTRY(MODE_NOT_FOUND, "Cipher mode not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(MODE_NOT_AVAILABLE, "Cipher mode %s is not available in installed OpenSSL library")
PHP_CRYPTO_ERROR_INFO_ENTRY(AUTHENTICATION_NOT_SUPPORTED, "The authentication is not supported for %s cipher mode")
PHP_CRYPTO_ERROR_INFO_ENTRY(KEY_LENGTH_INVALID, "Invalid length of key for cipher '%s' algorithm (required length: %d)")
PHP_CRYPTO_ERROR_INFO_ENTRY(IV_LENGTH_INVALID, "Invalid length of initial vector for cipher '%s' algorithm (required length: %d)")
PHP_CRYPTO_ERROR_INFO_ENTRY(AAD_SETTER_FORBIDDEN, "AAD setter has to be called before encryption or decryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(AAD_SETTER_FAILED, "AAD setter failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_GETTER_FORBIDDEN, "Tag getter has to be called after encryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_SETTER_FORBIDDEN, "Tag setter has to be called before decryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_GETTER_FAILED, "Tag getter failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_SETTER_FAILED, "Tag setter failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_LENGTH_LOW, "Tag length can't be lower than 32 bits (4 characters)")
PHP_CRYPTO_ERROR_INFO_ENTRY(TAG_LENGTH_HIGH, "Tag length can't exceed 128 bits (16 characters)")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_ALG_FAILED, "Initialization of cipher algorithm failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_CTX_FAILED, "Initialization of cipher context failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_ENCRYPT_FORBIDDEN, "Cipher object is already used for decryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_DECRYPT_FORBIDDEN, "Cipher object is already used for encryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(UPDATE_FAILED, "Updating of cipher failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(UPDATE_ENCRYPT_FORBIDDEN, "Cipher object is not initialized for encryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(UPDATE_DECRYPT_FORBIDDEN, "Cipher object is not initialized for decryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(FINISH_FAILED, "Finalizing of cipher failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(FINISH_ENCRYPT_FORBIDDEN, "Cipher object is not initialized for encryption")
PHP_CRYPTO_ERROR_INFO_ENTRY(FINISH_DECRYPT_FORBIDDEN, "Cipher object is not initialized for decryption")
PHP_CRYPTO_ERROR_INFO_END()

PHP_CRYPTO_EXCEPTION_DEFINE(Hash)
PHP_CRYPTO_ERROR_INFO_BEGIN(Hash)
PHP_CRYPTO_ERROR_INFO_ENTRY(ALGORITHM_NOT_FOUND, "Hash algorithm '%s' not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_NOT_FOUND, "Hash static method '%s' not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_TOO_MANY_ARGS, "Hash static method %s can accept max one argument")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_FAILED, "Initialization of hash failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(UPDATE_FAILED, "Updating of hash context failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(DIGEST_FAILED, "Creating of hash digest failed")
PHP_CRYPTO_ERROR_INFO_END()


ZEND_BEGIN_ARG_INFO(arginfo_crypto_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_alg_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_alg_list, 0, 0, 0)
ZEND_ARG_INFO(0, aliases)
ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_alg_static, 0)
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

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_get_tag, 0)
ZEND_ARG_INFO(0, tag_size)
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

static const zend_function_entry php_crypto_algorithm_object_methods[] = {
	PHP_CRYPTO_ME(Algorithm, __construct,       arginfo_crypto_algorithm,      ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Algorithm, getAlgorithmName,  NULL,                          ZEND_ACC_PUBLIC)
	PHPC_FE_END
};

static const zend_function_entry php_crypto_cipher_object_methods[] = {
	PHP_CRYPTO_ME(Cipher, getAlgorithms,    arginfo_crypto_alg_list,           ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, hasAlgorithm,     arginfo_crypto_algorithm,          ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, hasMode,          arginfo_crypto_cipher_mode,        ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, __callStatic,     arginfo_crypto_alg_static,         ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, __construct,      arginfo_crypto_cipher_construct,   ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptInit,      arginfo_crypto_cipher_init,        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptUpdate,    arginfo_crypto_alg_data,           ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptFinish,    NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encrypt,          arginfo_crypto_cipher_crypt,       ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptInit,      arginfo_crypto_cipher_init,        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptUpdate,    arginfo_crypto_alg_data,           ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptFinish,    NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decrypt,          arginfo_crypto_cipher_crypt,       ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getBlockSize,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getKeyLength,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getIVLength,      NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getMode,          NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getTag,           arginfo_crypto_cipher_get_tag,     ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, setTag,           arginfo_crypto_cipher_set_tag,     ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, setAAD,           arginfo_crypto_cipher_set_aad,     ZEND_ACC_PUBLIC)
	PHPC_FE_END
};

static const zend_function_entry php_crypto_hash_object_methods[] = {
	PHP_CRYPTO_ME(Hash, getAlgorithms,    arginfo_crypto_alg_list,             ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, hasAlgorithm,     arginfo_crypto_algorithm,            ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, __callStatic,     arginfo_crypto_alg_static,           ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, __construct,      arginfo_crypto_algorithm,            ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, update,           arginfo_crypto_alg_data,             ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, digest,           NULL,                                ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, hexdigest,        NULL,                                ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, getSize,          NULL,                                ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Hash, getBlockSize,     NULL,                                ZEND_ACC_PUBLIC)
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
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(GCM, 1,
			EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_SET_TAG, EVP_CTRL_GCM_GET_TAG)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(GCM)
#endif
#ifdef EVP_CIPH_CCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(CCM, 1,
			EVP_CTRL_CCM_SET_IVLEN, EVP_CTRL_CCM_SET_TAG, EVP_CTRL_CCM_GET_TAG)
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

/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_hash_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_hmac_ce;
#ifdef PHP_CRYPTO_HAS_CMAC
PHP_CRYPTO_API zend_class_entry *php_crypto_cmac_ce;
#endif

/* exception entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_exception_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_alg);

/* algorithm name getter macros */
#define PHP_CRYPTO_GET_ALGORITHM_NAME_EX(this_object) \
	zend_read_property(php_crypto_algorithm_ce, this_object, \
		"algorithm", sizeof("algorithm")-1, 1 TSRMLS_CC)

#define PHP_CRYPTO_GET_ALGORITHM_NAME(this_object) \
	Z_STRVAL_P(PHP_CRYPTO_GET_ALGORITHM_NAME_EX(this_object))

/* {{{ crypto_alg free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_alg)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_alg);

	if (PHPC_THIS->type == PHP_CRYPTO_ALG_CIPHER) {
		EVP_CIPHER_CTX_cleanup(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));
		efree(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));
	} else if (PHPC_THIS->type == PHP_CRYPTO_ALG_HASH) {
		EVP_MD_CTX_cleanup(PHP_CRYPTO_HASH_CTX(PHPC_THIS));
		efree(PHP_CRYPTO_HASH_CTX(PHPC_THIS));
	} else if (PHPC_THIS->type == PHP_CRYPTO_ALG_HMAC) {
		HMAC_CTX_cleanup(PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
		efree(PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (PHPC_THIS->type == PHP_CRYPTO_ALG_CMAC) {
		CMAC_CTX_cleanup(PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
		efree(PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
	}
#endif

	if (PHP_CRYPTO_CIPHER_AAD(PHPC_THIS)) {
		efree(PHP_CRYPTO_CIPHER_AAD(PHPC_THIS));
	}
	if (PHP_CRYPTO_CIPHER_TAG(PHPC_THIS)) {
		efree(PHP_CRYPTO_CIPHER_TAG(PHPC_THIS));
	}

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_alg create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_alg)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_alg);

	if (PHPC_CLASS_TYPE == php_crypto_cipher_ce) {
		PHPC_THIS->type = PHP_CRYPTO_ALG_CIPHER;
		PHP_CRYPTO_CIPHER_CTX(PHPC_THIS) = (EVP_CIPHER_CTX *) emalloc(sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));
	} else if (PHPC_CLASS_TYPE == php_crypto_hash_ce) {
		PHPC_THIS->type = PHP_CRYPTO_ALG_HASH;
		PHP_CRYPTO_HASH_CTX(PHPC_THIS) = (EVP_MD_CTX *) emalloc(sizeof(EVP_MD_CTX));
		EVP_MD_CTX_init(PHP_CRYPTO_HASH_CTX(PHPC_THIS));
	} else if (PHPC_CLASS_TYPE == php_crypto_hmac_ce) {
		PHPC_THIS->type = PHP_CRYPTO_ALG_HMAC;
		PHP_CRYPTO_HMAC_CTX(PHPC_THIS) = (HMAC_CTX *) emalloc(sizeof(HMAC_CTX));
		HMAC_CTX_init(PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (class_type == php_crypto_cmac_ce) {
		PHPC_THIS->type = PHP_CRYPTO_ALG_CMAC;
		PHP_CRYPTO_CMAC_CTX(PHPC_THIS) = (CMAC_CTX *) emalloc(sizeof(CMAC_CTX));
		CMAC_CTX_init(PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
	}
#endif
	else {
		PHPC_THIS->type = PHP_CRYPTO_ALG_NONE;
	}

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(crypto_alg);
}
/* }}} */

/* {{{ crypto_alg create object handler */
PHPC_OBJ_HANDLER_CREATE(crypto_alg)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(crypto_alg);
}
/* }}} */

/* {{{ crypto_alg clone object handler */
PHPC_OBJ_HANDLER_CLONE(crypto_alg)
{
	zend_bool copy_success;
	PHPC_OBJ_HANDLER_CLONE_INIT(crypto_alg);

	PHPC_THAT->status = PHPC_THIS->status;
	PHPC_THAT->type = PHPC_THIS->type;

	if (PHPC_THAT->type == PHP_CRYPTO_ALG_CIPHER) {
#ifdef PHP_CRYPTO_HAS_CIPHER_CTX_COPY
		copy_success = EVP_CIPHER_CTX_copy(
				PHP_CRYPTO_CIPHER_CTX(PHPC_THAT), PHP_CRYPTO_CIPHER_CTX(PHPC_THIS));
#else
		memcpy(PHP_CRYPTO_CIPHER_CTX(PHPC_THAT),
				PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), sizeof *(PHP_CRYPTO_CIPHER_CTX(PHPC_THAT)));
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
		PHP_CRYPTO_CIPHER_ALG(PHPC_THAT) = PHP_CRYPTO_CIPHER_CTX(PHPC_THIS)->cipher;
	} else if (PHPC_THAT->type == PHP_CRYPTO_ALG_HASH) {
		copy_success = EVP_MD_CTX_copy(
				PHP_CRYPTO_HASH_CTX(PHPC_THAT), PHP_CRYPTO_HASH_CTX(PHPC_THIS));
		PHP_CRYPTO_HASH_ALG(PHPC_THAT) = PHP_CRYPTO_HASH_CTX(PHPC_THIS)->digest;
	} else if (PHPC_THAT->type == PHP_CRYPTO_ALG_HMAC) {
#ifdef PHP_CRYPTO_HAS_CIPHER_CTX_COPY
		copy_success = HMAC_CTX_copy(
				PHP_CRYPTO_HMAC_CTX(PHPC_THAT), PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
#else
		copy_success = 0;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->i_ctx,
				&PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->i_ctx))
			goto copy_end;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->o_ctx,
				&PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->o_ctx))
			goto copy_end;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->md_ctx,
				&PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->md_ctx))
			goto copy_end;
		memcpy(PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->key,
				PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->key, HMAC_MAX_MD_CBLOCK);
		PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->key_length = PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->key_length;
		PHP_CRYPTO_HMAC_CTX(PHPC_THAT)->md = PHP_CRYPTO_HMAC_CTX(PHPC_THIS)->md;
		copy_success = 1;
#endif
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (PHPC_THAT->type == PHP_CRYPTO_ALG_CMAC) {
		copy_success = CMAC_CTX_copy(
				PHP_CRYPTO_CMAC_CTX(PHPC_THAT), PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
	}
#endif
	else {
		copy_success = 0;
	}

copy_end:
	if (!copy_success) {
		php_error(E_ERROR, "Cloning of Algorithm object failed");
	}

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_alg)
{
	zend_class_entry ce;
	const php_crypto_cipher_mode *mode;

	/* Algorithm class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Algorithm), php_crypto_algorithm_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, crypto_alg);
	php_crypto_algorithm_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(crypto_alg);
	PHPC_OBJ_SET_HANDLER_OFFSET(crypto_alg);
	PHPC_OBJ_SET_HANDLER_FREE(crypto_alg);
	PHPC_OBJ_SET_HANDLER_CLONE(crypto_alg);
	zend_declare_property_null(php_crypto_algorithm_ce,
			"algorithm", sizeof("algorithm")-1, ZEND_ACC_PROTECTED TSRMLS_CC);

	/* AlgorithmException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, Algorithm);

	/* CipherException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, Cipher,  Algorithm);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Cipher);

	/* HashException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, Hash,  Algorithm);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Hash);

	/* Cipher class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Cipher), php_crypto_cipher_object_methods);
	php_crypto_cipher_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_algorithm_ce, NULL);
	/* Cipher constants for modes */
	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		zend_declare_class_constant_long(php_crypto_cipher_ce,
				mode->constant, strlen(mode->constant), mode->value TSRMLS_CC);
	}

	/* Hash class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Hash), php_crypto_hash_object_methods);
	php_crypto_hash_ce = zend_register_internal_class_ex(&ce,
			php_crypto_algorithm_ce, NULL TSRMLS_CC);

	/* HMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(HMAC), NULL);
	php_crypto_hmac_ce = zend_register_internal_class_ex(&ce, php_crypto_hash_ce, NULL TSRMLS_CC);

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(CMAC), NULL);
	php_crypto_cmac_ce = zend_register_internal_class_ex(&ce, php_crypto_hash_ce, NULL TSRMLS_CC);
#endif

	return SUCCESS;
}
/* }}} */

/* ALGORITHM METHODS */

/* do all parameter structure */
typedef struct {
	zend_bool aliases;
	char *prefix;
	int prefix_len;
	zval *return_value;
} php_crypto_do_all_algorithms_param;

/* {{{ php_crypto_do_all_algorithms */
static void php_crypto_do_all_algorithms(const OBJ_NAME *name, void *arg)
{
	php_crypto_do_all_algorithms_param *pp = (php_crypto_do_all_algorithms_param *) arg;
	if ((pp->aliases || name->alias == 0) &&
			(!pp->prefix || !strncmp(name->name, pp->prefix, pp->prefix_len))) {
		add_next_index_string(pp->return_value, (char *) name->name, 1);
	}
}
/* }}} */

/* {{{ php_crypto_get_algorithms */
static void php_crypto_get_algorithms(INTERNAL_FUNCTION_PARAMETERS, int type)
{
	php_crypto_do_all_algorithms_param param = { 0, NULL, 0, return_value };

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|bs",
			&param.aliases, &param.prefix, &param.prefix_len) == FAILURE) {
		return;
	}
	array_init(return_value);
	OBJ_NAME_do_all_sorted(type, php_crypto_do_all_algorithms, &param);
}
/* }}} */

/* {{{ php_crypto_get_algorithm_object_ex */
static inline void php_crypto_set_algorithm_name(zval *object,
		char *algorithm, phpc_str_size_t algorithm_len TSRMLS_DC)
{
	php_strtoupper(algorithm, algorithm_len);
	zend_update_property_stringl(php_crypto_algorithm_ce, object,
			"algorithm", sizeof("algorithm")-1, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ proto Crypto\Algorithm::__construct(string $algorithm)
   Algorithm constructor */
PHP_CRYPTO_METHOD(Algorithm, __construct)
{
	char *algorithm;
	phpc_str_size_t algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&algorithm, &algorithm_len) == FAILURE) {
		return;
	}
	php_crypto_set_algorithm_name(getThis(), algorithm, algorithm_len TSRMLS_CC);
}

/* {{{ proto string Crypto\Algorithm::getAlgorithmName()
   Returns algorithm string */
PHP_CRYPTO_METHOD(Algorithm, getAlgorithmName)
{
	zval *algorithm = PHP_CRYPTO_GET_ALGORITHM_NAME_EX(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
}
/* }}} */


/* CIPHER METHODS */

/* {{{ php_crypto_get_cipher_algorithm */
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm(char *algorithm, int algorithm_len)
{
	const EVP_CIPHER *cipher;
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
			php_crypto_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
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
		php_crypto_set_algorithm_name(object, alg_buf.c, alg_buf.len TSRMLS_CC);
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
static int php_crypto_set_cipher_algorithm_ex(PHPC_THIS_DECLARE(crypto_alg),
		char *algorithm, int algorithm_len TSRMLS_DC)
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
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_alg, object);
	php_crypto_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
	return php_crypto_set_cipher_algorithm_ex(PHPC_THIS, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_from_params_ex */
static int php_crypto_set_cipher_algorithm_from_params_ex(
		zval *object, char *algorithm, phpc_str_size_t algorithm_len,
		zval *pz_mode, zval *pz_key_size, zend_bool is_static TSRMLS_DC)
{
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_alg, object);
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
		zval *object, char *algorithm, int algorithm_len,
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
static int php_crypto_cipher_is_mode_authenticated(PHPC_THIS_DECLARE(crypto_alg) TSRMLS_DC)
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
static int php_crypto_cipher_check_tag_len(long tag_len TSRMLS_DC)
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
static int php_crypto_cipher_check_key_len(zval *zobject, PHPC_THIS_DECLARE(crypto_alg),
		int key_len TSRMLS_DC)
{
	int alg_key_len = EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));

	if (key_len != alg_key_len &&
			!EVP_CIPHER_CTX_set_key_length(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), key_len)) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, KEY_LENGTH_INVALID),
				PHP_CRYPTO_GET_ALGORITHM_NAME(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_iv_len */
static int php_crypto_cipher_check_iv_len(zval *zobject, PHPC_THIS_DECLARE(crypto_alg),
		const php_crypto_cipher_mode *mode, int iv_len TSRMLS_DC)
{
	int alg_iv_len = EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	if (iv_len == alg_iv_len) {
		return SUCCESS;
	}

	if (!mode->auth_enc ||
			!EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
				mode->auth_ivlen_flag, iv_len, NULL)) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Cipher, IV_LENGTH_INVALID),
				PHP_CRYPTO_GET_ALGORITHM_NAME(zobject), alg_iv_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_init_ex */
static PHPC_OBJ_STRUCT_NAME(crypto_alg) *php_crypto_cipher_init_ex(
		zval *zobject, char *key, int key_len, char *iv, int iv_len, int enc TSRMLS_DC)
{
	const php_crypto_cipher_mode *mode;
	PHPC_THIS_DECLARE_AND_FETCH_FROM_ZVAL(crypto_alg, zobject);

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

	/* check initialization vector length */
	if (php_crypto_cipher_check_iv_len(zobject, PHPC_THIS, mode, iv_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* initialize encryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), NULL, NULL,
			(unsigned char *) key, (unsigned char *) iv, enc)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, INIT_CTX_FAILED));
		return NULL;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(PHPC_THIS, enc, INIT);

	if (mode->auth_enc && !enc &&
			php_crypto_cipher_set_tag(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), mode,
				PHP_CRYPTO_CIPHER_TAG(PHPC_THIS),
				PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	return PHPC_THIS;
}
/* }}} */

/* {{{ php_crypto_cipher_init */
static inline void php_crypto_cipher_init(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	char *key, *iv = NULL;
	int key_len, iv_len = 0;

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

/* {{{ php_crypto_cipher_update */
static inline void php_crypto_cipher_update(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	PHPC_THIS_DECLARE(crypto_alg);
	PHPC_STR_DECLARE(out);
	const php_crypto_cipher_mode *mode;
	char *data;
	phpc_str_size_t data_len, out_len, update_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);

	/* check algorithm status */
	if (enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_ENCRYPT_FORBIDDEN));
		RETURN_FALSE;
	} else if (!enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(PHPC_THIS)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_DECRYPT_FORBIDDEN));
		RETURN_FALSE;
	}

	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	if (mode->auth_enc && !php_crypto_cipher_write_aad(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			PHP_CRYPTO_CIPHER_AAD(PHPC_THIS),
			PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	out_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	update_len = out_len;
	PHPC_STR_ALLOC(out, out_len);

	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &update_len,
			(unsigned char *) data, data_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_FAILED));
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
	PHPC_THIS_DECLARE(crypto_alg);
	PHPC_STR_DECLARE(out);
	int out_len, final_len;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);

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

	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &final_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_FAILED));
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
	PHPC_THIS_DECLARE(crypto_alg);
	PHPC_STR_DECLARE(out);
	const php_crypto_cipher_mode *mode;
	char *data, *key, *iv = NULL;
	phpc_str_size_t out_len, update_len, final_len, data_len, key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s",
			&data, &data_len, &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	PHPC_THIS = php_crypto_cipher_init_ex(getThis(), key, key_len, iv, iv_len, enc TSRMLS_CC);
	if (PHPC_THIS == NULL) {
		RETURN_FALSE;
	}

	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));

	if (mode->auth_enc && !php_crypto_cipher_write_aad(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			PHP_CRYPTO_CIPHER_AAD(PHPC_THIS),
			PHP_CRYPTO_CIPHER_AAD_LEN(PHPC_THIS) TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	out_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS));
	PHPC_STR_ALLOC(out, out_len);

	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) PHPC_STR_VAL(out), &update_len,
			(unsigned char *) data, data_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, UPDATE_FAILED));
		PHPC_STR_RELEASE(out);
		RETURN_FALSE;
	}
	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS),
			(unsigned char *) (PHPC_STR_VAL(out) + update_len), &final_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, FINISH_FAILED));
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

/* {{{ proto static string Crypto\Cipher::getAlgorithms(bool $aliases = false, string $prefix = null)
   Returns cipher algorithms */
PHP_CRYPTO_METHOD(Cipher, getAlgorithms)
{
	php_crypto_get_algorithms(INTERNAL_FUNCTION_PARAM_PASSTHRU, OBJ_NAME_TYPE_CIPHER_METH);
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
	long mode;

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
	char *algorithm;
	int algorithm_len;
	zval *mode = NULL, *key_size = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zz",
			&algorithm, &algorithm_len, &mode, &key_size) == FAILURE) {
		return;
	}
	php_crypto_set_cipher_algorithm_from_params(
			getThis(), algorithm, algorithm_len, mode, key_size TSRMLS_CC);
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
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getKeyLength()
   Returns cipher key length */
PHP_CRYPTO_METHOD(Cipher, getKeyLength)
{
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getIVLength()
   Returns cipher IV length */
PHP_CRYPTO_METHOD(Cipher, getIVLength)
{
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Cipher::getMode()
   Returns cipher mode */
PHP_CRYPTO_METHOD(Cipher, getMode)
{
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
}
/* }}} */

/* {{{ proto string Crypto\Cipher::getTag(int $tag_size)
   Returns authentication tag */
PHP_CRYPTO_METHOD(Cipher, getTag)
{
	PHPC_THIS_DECLARE(crypto_alg);
	const php_crypto_cipher_mode *mode;
	PHPC_STR_DECLARE(tag);
	phpc_long_t tag_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &tag_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE ||
			php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status != PHP_CRYPTO_ALG_STATUS_ENCRYPT_FINAL) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_GETTER_FORBIDDEN));
		RETURN_FALSE;
	}

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
	PHPC_THIS_DECLARE(crypto_alg);
	const php_crypto_cipher_mode *mode;
	char *tag;
	phpc_str_size_t tag_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &tag, &tag_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(PHPC_THIS));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE ||
			php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status == PHP_CRYPTO_ALG_STATUS_CLEAR) {
		if (!PHP_CRYPTO_CIPHER_TAG(PHPC_THIS)) {
			PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) = emalloc(tag_len + 1);
		} else if (PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) < tag_len) {
			PHP_CRYPTO_CIPHER_TAG(PHPC_THIS) = erealloc(
					PHP_CRYPTO_CIPHER_TAG(PHPC_THIS), tag_len + 1);
		}
		memcpy(PHP_CRYPTO_CIPHER_TAG(PHPC_THIS), tag, tag_len + 1);
		PHP_CRYPTO_CIPHER_TAG_LEN(PHPC_THIS) = tag_len;
	} else if (PHPC_THIS->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT) {
		php_crypto_cipher_set_tag(PHP_CRYPTO_CIPHER_CTX(PHPC_THIS), mode,
				(unsigned char *) tag, tag_len TSRMLS_CC);
	} else {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Cipher, TAG_SETTER_FORBIDDEN));
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool Crypto\Cipher::setAAD(string $aad)
   Sets additional application data for authenticated encryption */
PHP_CRYPTO_METHOD(Cipher, setAAD)
{
	PHPC_THIS_DECLARE(crypto_alg);
	char *aad;
	int aad_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &aad, &aad_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	if (php_crypto_cipher_is_mode_authenticated(PHPC_THIS TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	if (PHPC_THIS->status == PHP_CRYPTO_ALG_STATUS_CLEAR ||
			PHPC_THIS->status == PHP_CRYPTO_ALG_STATUS_ENCRYPT_INIT ||
			PHPC_THIS->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT) {
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

/* HASH METHODS */

/* {{{ php_crypto_hash_bin2hex */
PHP_CRYPTO_API void php_crypto_hash_bin2hex(char *out, const unsigned char *in, unsigned in_len)
{
	static const char hexits[17] = "0123456789abcdef";
	unsigned i;
	for (i = 0; i < in_len; i++) {
		out[i * 2]       = hexits[in[i] >> 4];
		out[(i * 2) + 1] = hexits[in[i] &  0x0F];
	}
	out[i * 2] = 0;
}
/* }}} */

/* {{{ php_crypto_hash_init */
static inline int php_crypto_hash_init(PHPC_THIS_DECLARE(crypto_alg) TSRMLS_DC)
{
	/* initialize hash */
	if (!EVP_DigestInit_ex(PHP_CRYPTO_HASH_CTX(PHPC_THIS), PHP_CRYPTO_HASH_ALG(PHPC_THIS), NULL)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, INIT_FAILED));
		return FAILURE;
	}
	PHPC_THIS->status = PHP_CRYPTO_ALG_STATUS_HASH;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_update */
static inline int php_crypto_hash_update(PHPC_THIS_DECLARE(crypto_alg),
		char *data, phpc_str_size_t data_len TSRMLS_DC)
{
	/* check if hash is initialized and if it's not, then try to initialize */
	if (PHPC_THIS->status != PHP_CRYPTO_ALG_STATUS_HASH &&
			php_crypto_hash_init(PHPC_THIS TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	/* update hash context */
	if (!EVP_DigestUpdate(PHP_CRYPTO_HASH_CTX(PHPC_THIS), data, data_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, UPDATE_FAILED));
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_digest */
static inline void php_crypto_hash_digest(INTERNAL_FUNCTION_PARAMETERS, int encode_to_hex)
{
	PHPC_THIS_DECLARE(crypto_alg);
	PHPC_STR_DECLARE(hash);
	unsigned char hash_value[EVP_MAX_MD_SIZE + 1];
	unsigned int hash_len;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);

	/* check if hash is initialized and if it's not, then try to initialize */
	if (PHPC_THIS->status != PHP_CRYPTO_ALG_STATUS_HASH &&
			php_crypto_hash_init(PHPC_THIS TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	/* finalize hash context */
	if (!EVP_DigestFinal(PHP_CRYPTO_HASH_CTX(PHPC_THIS), hash_value, &hash_len)) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, DIGEST_FAILED));
		RETURN_FALSE;
	}
	hash_value[hash_len] = 0;
	PHPC_THIS->status = PHP_CRYPTO_ALG_STATUS_CLEAR;

	if (encode_to_hex) {
		unsigned int hash_hex_len = hash_len * 2;
		PHPC_STR_ALLOC(hash, hash_hex_len);
		php_crypto_hash_bin2hex(PHPC_STR_VAL(hash), hash_value, hash_len);
	} else {
		PHPC_STR_INIT(hash, hash_value, hash_len);
	}

	PHPC_STR_RETURN(hash);
}
/* }}} */

/* {{{ proto static string Crypto\Hash::getAlgorithms(bool $aliases = false, string $prefix = null)
   Returns hash algorithms */
PHP_CRYPTO_METHOD(Hash, getAlgorithms)
{
	php_crypto_get_algorithms(INTERNAL_FUNCTION_PARAM_PASSTHRU, OBJ_NAME_TYPE_MD_METH);
}
/* }}} */

/* {{{ proto static bool Crypto\Hash::hasAlgorithm(string $algorithm)
   Finds out whether algorithm exists */
PHP_CRYPTO_METHOD(Hash, hasAlgorithm)
{
	char *algorithm;
	phpc_str_size_t algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	if (EVP_get_digestbyname(algorithm)) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto static Crypto\Hash::__callStatic(string $name, array $arguments)
   Hash magic method for calling static methods */
PHP_CRYPTO_METHOD(Hash, __callStatic)
{
	char *algorithm;
	phpc_str_size_t algorithm_len;
	int argc;
	zval *args, *pz_arg;
	phpc_val *ppv_arg;
	const EVP_MD *digest;
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa",
			&algorithm, &algorithm_len, &args) == FAILURE) {
		return;
	}

	argc = PHPC_HASH_NUM_ELEMENTS(Z_ARRVAL_P(args));
	if (argc > 1) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Hash, STATIC_METHOD_TOO_MANY_ARGS), algorithm);
		RETURN_FALSE;
	}

	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Hash, STATIC_METHOD_NOT_FOUND), algorithm);
		RETURN_FALSE;
	}

	object_init_ex(return_value, php_crypto_hash_ce);
	php_crypto_set_algorithm_name(return_value, algorithm, algorithm_len TSRMLS_CC);
	PHPC_THIS_FETCH_FROM_ZVAL(crypto_alg, return_value);
	PHP_CRYPTO_HASH_ALG(PHPC_THIS) = digest;

	if (argc == 1) {
		PHPC_HASH_INTERNAL_POINTER_RESET(Z_ARRVAL_P(args));
		PHPC_HASH_GET_CURRENT_DATA(Z_ARRVAL_P(args), ppv_arg);
		convert_to_string_ex(ppv_arg);
		PHPC_PVAL_TO_PZVAL(ppv_arg, pz_arg);
		if (php_crypto_hash_update(PHPC_THIS,
				Z_STRVAL_P(pz_arg), Z_STRLEN_P(pz_arg) TSRMLS_CC) == FAILURE) {
			RETURN_NULL();
		}
	}
}
/* }}} */

/* {{{ proto Crypto\Hash::__construct(string $algorithm)
   Hash constructor */
PHP_CRYPTO_METHOD(Hash, __construct)
{
	PHPC_THIS_DECLARE(crypto_alg);
	char *algorithm;
	phpc_str_size_t algorithm_len;
	const EVP_MD *digest;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	php_crypto_set_algorithm_name(getThis(), algorithm, algorithm_len TSRMLS_CC);
	PHPC_THIS_FETCH(crypto_alg);

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC algorithm uses a cipher algorithm */
	if (PHPC_THIS->type == PHP_CRYPTO_ALG_CMAC) {
		php_crypto_set_cipher_algorithm_ex(PHPC_THIS, algorithm, algorithm_len TSRMLS_CC);
		return;
	}
#endif

	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Hash, ALGORITHM_NOT_FOUND), algorithm);
		return;
	}
	PHP_CRYPTO_HASH_ALG(PHPC_THIS) = digest;
}
/* }}} */

/* {{{ proto void Crypto\Hash::update(string $data)
   Updates hash */
PHP_CRYPTO_METHOD(Hash, update)
{
	PHPC_THIS_DECLARE(crypto_alg);
	char *data;
	phpc_str_size_t data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	php_crypto_hash_update(PHPC_THIS, data, data_len TSRMLS_CC);
	ZVAL_ZVAL(return_value, getThis(), 1, 0);
}
/* }}} */

/* {{{ proto string Crypto\Hash::digest()
   Return hash digest in raw foramt */
PHP_CRYPTO_METHOD(Hash, digest)
{
	php_crypto_hash_digest(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}
/* }}} */

/* {{{ proto string Crypto\Hash::hexdigest()
   Return hash digest in hex format */
PHP_CRYPTO_METHOD(Hash, hexdigest)
{
	php_crypto_hash_digest(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}
/* }}} */

/* {{{ proto int Crypto\Hash::getBlockSize()
   Returns hash block size */
PHP_CRYPTO_METHOD(Hash, getBlockSize)
{
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(EVP_MD_block_size(PHP_CRYPTO_HASH_ALG(PHPC_THIS)));
}

/* {{{ proto int Crypto\Hash::getSize()
   Returns hash size */
PHP_CRYPTO_METHOD(Hash, getSize)
{
	PHPC_THIS_DECLARE(crypto_alg);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_alg);
	RETURN_LONG(EVP_MD_size(PHP_CRYPTO_HASH_ALG(PHPC_THIS)));
}
