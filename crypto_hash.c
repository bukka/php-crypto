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
#include "php_crypto_hash.h"
#include "php_crypto_cipher.h"
#include "php_crypto_object.h"
#include "zend_exceptions.h"
#include "ext/standard/php_string.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define PHP_CRYPTO_HMAC_DO(_rc, _method) \
	_rc = _method
#else
#define PHP_CRYPTO_HMAC_DO(_rc, _method) \
	_rc = 1; _method

int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)
{
	if (!EVP_MD_CTX_copy(&dctx->i_ctx, &sctx->i_ctx))
		goto err;
	if (!EVP_MD_CTX_copy(&dctx->o_ctx, &sctx->o_ctx))
		goto err;
	if (!EVP_MD_CTX_copy(&dctx->md_ctx, &sctx->md_ctx))
		goto err;
	memcpy(dctx->key, sctx->key, HMAC_MAX_MD_CBLOCK);
	dctx->key_length = sctx->key_length;
	dctx->md = sctx->md;
	return 1;
 err:
	return 0;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static HMAC_CTX *HMAC_CTX_new()
{
	HMAC_CTX *ctx = OPENSSL_malloc(sizeof(HMAC_CTX));
	if (ctx) {
		HMAC_CTX_init(ctx);
	}

	return ctx;
}

static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	OPENSSL_free(ctx);
}

#endif

PHP_CRYPTO_EXCEPTION_DEFINE(Hash)
PHP_CRYPTO_ERROR_INFO_BEGIN(Hash)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	HASH_ALGORITHM_NOT_FOUND,
	"Hash algorithm '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_NOT_FOUND,
	"Hash static method '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_TOO_MANY_ARGS,
	"Hash static method %s can accept max one argument"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_FAILED,
	"Initialization of hash failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_FAILED,
	"Updating of hash context failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	DIGEST_FAILED,
	"Creating of hash digest failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INPUT_DATA_LENGTH_HIGH,
	"Input data length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_END()


ZEND_BEGIN_ARG_INFO(arginfo_crypto_hash_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_hash_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_hash_list, 0, 0, 0)
ZEND_ARG_INFO(0, aliases)
ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_hash_static, 0)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, arguments)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_hash_object_methods[] = {
	PHP_CRYPTO_ME(
		Hash, getAlgorithms,
		arginfo_crypto_hash_list,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, hasAlgorithm,
		arginfo_crypto_hash_algorithm,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, __callStatic,
		arginfo_crypto_hash_static,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, __construct,
		arginfo_crypto_hash_algorithm,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, update,
		arginfo_crypto_hash_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, getAlgorithmName,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, digest,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, hexdigest,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, getSize,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Hash, getBlockSize,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

PHP_CRYPTO_EXCEPTION_DEFINE(MAC)
PHP_CRYPTO_ERROR_INFO_BEGIN(MAC)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	MAC_ALGORITHM_NOT_FOUND,
	"MAC algorithm '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	KEY_LENGTH_INVALID,
	"The key length for MAC is invalid"
)
PHP_CRYPTO_ERROR_INFO_END()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_mac_construct, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_mac_object_methods[] = {
	PHP_CRYPTO_ME(
		MAC, __construct,
		arginfo_crypto_mac_construct,
		ZEND_ACC_PUBLIC
	)
	PHPC_FE_END
};

/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_hash_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_mac_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_hmac_ce;
#ifdef PHP_CRYPTO_HAS_CMAC
PHP_CRYPTO_API zend_class_entry *php_crypto_cmac_ce;
#endif

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_hash);

/* algorithm name getter macros */
#define PHP_CRYPTO_HASH_GET_ALGORITHM_NAME_EX(this_object) \
	PHPC_READ_PROPERTY(php_crypto_hash_ce, this_object, \
		"algorithm", sizeof("algorithm")-1, 1)

#define PHP_CRYPTO_HASH_GET_ALGORITHM_NAME(this_object) \
	Z_STRVAL_P(PHP_CRYPTO_HASH_GET_ALGORITHM_NAME_EX(this_object))

/* {{{ crypto_hash free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_hash)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_hash);

	if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_MD) {
		EVP_MD_CTX_destroy(PHP_CRYPTO_HASH_CTX(PHPC_THIS));
	} else if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_HMAC) {
		HMAC_CTX_free(PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_CMAC) {
		CMAC_CTX_free(PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
	}
#endif

	if (PHPC_THIS->key) {
		efree(PHPC_THIS->key);
	}

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_hash create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_hash)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_hash);

	if (PHPC_CLASS_TYPE == php_crypto_hash_ce) {
		PHPC_THIS->type = PHP_CRYPTO_HASH_TYPE_MD;
		PHP_CRYPTO_HASH_CTX(PHPC_THIS) = EVP_MD_CTX_create();
	} else if (PHPC_CLASS_TYPE == php_crypto_hmac_ce) {
		PHPC_THIS->type = PHP_CRYPTO_HASH_TYPE_HMAC;
		PHP_CRYPTO_HMAC_CTX(PHPC_THIS) = HMAC_CTX_new();
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (PHPC_CLASS_TYPE == php_crypto_cmac_ce) {
		PHPC_THIS->type = PHP_CRYPTO_HASH_TYPE_CMAC;
		PHP_CRYPTO_CMAC_CTX(PHPC_THIS) = CMAC_CTX_new();
	}
#endif
	else {
		PHPC_THIS->type = PHP_CRYPTO_HASH_TYPE_NONE;
	}

	PHPC_THIS->key = NULL;
	PHPC_THIS->key_len = 0;

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(crypto_hash);
}
/* }}} */

/* {{{ crypto_hash create object handler */
PHPC_OBJ_HANDLER_CREATE(crypto_hash)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(crypto_hash);
}
/* }}} */

/* {{{ crypto_hash clone object handler */
PHPC_OBJ_HANDLER_CLONE(crypto_hash)
{
	zend_bool copy_success;
	PHPC_OBJ_HANDLER_CLONE_INIT(crypto_hash);

	PHPC_THAT->status = PHPC_THIS->status;
	PHPC_THAT->type = PHPC_THIS->type;
	if (PHPC_THIS->key) {
		PHPC_THAT->key = emalloc(PHPC_THIS->key_len + 1);
		memcpy(PHPC_THAT->key, PHPC_THIS->key, PHPC_THIS->key_len + 1);
		PHPC_THAT->key_len = PHPC_THIS->key_len;
	}

	if (PHPC_THAT->type == PHP_CRYPTO_HASH_TYPE_MD) {
		copy_success = EVP_MD_CTX_copy(
				PHP_CRYPTO_HASH_CTX(PHPC_THAT), PHP_CRYPTO_HASH_CTX(PHPC_THIS));
		PHP_CRYPTO_HASH_ALG(PHPC_THAT) = EVP_MD_CTX_md(PHP_CRYPTO_HASH_CTX(PHPC_THIS));
	} else if (PHPC_THAT->type == PHP_CRYPTO_HASH_TYPE_HMAC) {
		copy_success = HMAC_CTX_copy(
				PHP_CRYPTO_HMAC_CTX(PHPC_THAT), PHP_CRYPTO_HMAC_CTX(PHPC_THIS));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (PHPC_THAT->type == PHP_CRYPTO_HASH_TYPE_CMAC) {
		copy_success = CMAC_CTX_copy(
				PHP_CRYPTO_CMAC_CTX(PHPC_THAT), PHP_CRYPTO_CMAC_CTX(PHPC_THIS));
	}
#endif
	else {
		copy_success = 0;
	}

	if (!copy_success) {
		php_error(E_ERROR, "Cloning of Hash object failed");
	}

	PHPC_OBJ_HANDLER_CLONE_RETURN();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_hash)
{
	zend_class_entry ce;

	/* Hash class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Hash), php_crypto_hash_object_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, crypto_hash);
	php_crypto_hash_ce = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(crypto_hash);
	PHPC_OBJ_SET_HANDLER_OFFSET(crypto_hash);
	PHPC_OBJ_SET_HANDLER_FREE(crypto_hash);
	PHPC_OBJ_SET_HANDLER_CLONE(crypto_hash);
	zend_declare_property_null(php_crypto_hash_ce,
			"algorithm", sizeof("algorithm")-1, ZEND_ACC_PROTECTED TSRMLS_CC);

	/* HashException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER(ce, Hash);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Hash);

	/* MAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(MAC), php_crypto_mac_object_methods);
	php_crypto_mac_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_hash_ce, NULL);
	php_crypto_mac_ce->ce_flags |= ZEND_ACC_EXPLICIT_ABSTRACT_CLASS;

	/* MACException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, MAC, Hash);
	PHP_CRYPTO_ERROR_INFO_REGISTER(MAC);

	/* HMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(HMAC), NULL);
	php_crypto_hmac_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_mac_ce, NULL);

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(CMAC), NULL);
	php_crypto_cmac_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_mac_ce, NULL);
#endif

	return SUCCESS;
}
/* }}} */

/* METHODS */

/* {{{ php_crypto_hash_set_algorithm_name */
static inline void php_crypto_hash_set_algorithm_name(zval *object,
		char *algorithm, phpc_str_size_t algorithm_len TSRMLS_DC)
{
	php_strtoupper(algorithm, algorithm_len);
	zend_update_property_stringl(php_crypto_hash_ce, object,
			"algorithm", sizeof("algorithm")-1, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

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
static inline int php_crypto_hash_init(PHPC_THIS_DECLARE(crypto_hash) TSRMLS_DC)
{
	int rc;

	if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_MD) {
		rc = EVP_DigestInit_ex(PHP_CRYPTO_HASH_CTX(PHPC_THIS),
				PHP_CRYPTO_HASH_ALG(PHPC_THIS), NULL);
	} else {
		 /* It is a MAC instance and the key is required */
		if (!PHPC_THIS->key) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, INIT_FAILED));
			return FAILURE;
		}

		/* update hash context */
		switch (PHPC_THIS->type) {
			case PHP_CRYPTO_HASH_TYPE_HMAC:
				PHP_CRYPTO_HMAC_DO(rc, HMAC_Init_ex)(
						PHP_CRYPTO_HMAC_CTX(PHPC_THIS),
						PHPC_THIS->key, PHPC_THIS->key_len,
						PHP_CRYPTO_HMAC_ALG(PHPC_THIS), NULL);

				break;
#ifdef PHP_CRYPTO_HAS_CMAC
			case PHP_CRYPTO_HASH_TYPE_CMAC:
				rc = CMAC_Init(PHP_CRYPTO_CMAC_CTX(PHPC_THIS),
						PHPC_THIS->key, PHPC_THIS->key_len,
						PHP_CRYPTO_CMAC_ALG(PHPC_THIS), NULL);
				break;
#endif
			default:
				rc = 0;
		}
	}

	/* initialize hash */
	if (!rc) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, INIT_FAILED));
		return FAILURE;
	}
	PHPC_THIS->status = PHP_CRYPTO_HASH_STATUS_HASH;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_update */
static inline int php_crypto_hash_update(PHPC_THIS_DECLARE(crypto_hash),
		char *data, phpc_str_size_t data_len TSRMLS_DC)
{
	int rc;

	/* check if hash is initialized and if it's not, then try to initialize */
	if (PHPC_THIS->status != PHP_CRYPTO_HASH_STATUS_HASH &&
			php_crypto_hash_init(PHPC_THIS TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	/* update hash context */
	switch (PHPC_THIS->type) {
		case PHP_CRYPTO_HASH_TYPE_MD:
			rc = EVP_DigestUpdate(PHP_CRYPTO_HASH_CTX(PHPC_THIS), data, data_len);
			break;
		case PHP_CRYPTO_HASH_TYPE_HMAC:
			PHP_CRYPTO_HMAC_DO(rc, HMAC_Update)(
					PHP_CRYPTO_HMAC_CTX(PHPC_THIS),
					(unsigned char *) data, data_len);
			break;
#ifdef PHP_CRYPTO_HAS_CMAC
		case PHP_CRYPTO_HASH_TYPE_CMAC:
			rc = CMAC_Update(PHP_CRYPTO_CMAC_CTX(PHPC_THIS), data, data_len);
			break;
#endif
		default:
			rc = 0;
	}

	if (!rc) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, UPDATE_FAILED));
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_digest */
static inline void php_crypto_hash_digest(INTERNAL_FUNCTION_PARAMETERS, int encode_to_hex)
{
	PHPC_THIS_DECLARE(crypto_hash);
	PHPC_STR_DECLARE(hash);
	unsigned char hash_value[EVP_MAX_MD_SIZE + 1];
	unsigned int hash_len;
	size_t hash_len_size;
	int rc;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_hash);

	/* check if hash is initialized and if it's not, then try to initialize */
	if (PHPC_THIS->status != PHP_CRYPTO_HASH_STATUS_HASH &&
			php_crypto_hash_init(PHPC_THIS TSRMLS_CC) == FAILURE) {
		RETURN_FALSE;
	}

	/* finalize hash context */
	switch (PHPC_THIS->type) {
		case PHP_CRYPTO_HASH_TYPE_MD:
			rc = EVP_DigestFinal(PHP_CRYPTO_HASH_CTX(PHPC_THIS), hash_value, &hash_len);
			break;
		case PHP_CRYPTO_HASH_TYPE_HMAC:
			PHP_CRYPTO_HMAC_DO(rc, HMAC_Final)(
					PHP_CRYPTO_HMAC_CTX(PHPC_THIS), hash_value, &hash_len);
			break;
#ifdef PHP_CRYPTO_HAS_CMAC
		case PHP_CRYPTO_HASH_TYPE_CMAC:
			rc = CMAC_Final(PHP_CRYPTO_CMAC_CTX(PHPC_THIS), hash_value, &hash_len_size);
			/* this is safe because the hash_len_size is always really small */
			hash_len = hash_len_size;
			break;
#endif
		default:
			rc = 0;
	}

	if (!rc) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, DIGEST_FAILED));
		RETURN_FALSE;
	}
	hash_value[hash_len] = 0;
	PHPC_THIS->status = PHP_CRYPTO_HASH_STATUS_CLEAR;

	if (encode_to_hex) {
		unsigned int hash_hex_len = hash_len * 2;
		PHPC_STR_ALLOC(hash, hash_hex_len);
		php_crypto_hash_bin2hex(PHPC_STR_VAL(hash), hash_value, hash_len);
	} else {
		PHPC_STR_INIT(hash, (char *) hash_value, hash_len);
	}

	PHPC_STR_RETURN(hash);
}
/* }}} */

/* {{{ proto static string Crypto\Hash::getAlgorithms(bool $aliases = false,
			string $prefix = null)
	Returns hash algorithms */
PHP_CRYPTO_METHOD(Hash, getAlgorithms)
{
	php_crypto_object_fn_get_names(INTERNAL_FUNCTION_PARAM_PASSTHRU, OBJ_NAME_TYPE_MD_METH);
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
	PHPC_THIS_DECLARE(crypto_hash);

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
	php_crypto_hash_set_algorithm_name(return_value, algorithm, algorithm_len TSRMLS_CC);
	PHPC_THIS_FETCH_FROM_ZVAL(crypto_hash, return_value);
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
	PHPC_THIS_DECLARE(crypto_hash);
	char *algorithm, *algorithm_uc;
	phpc_str_size_t algorithm_len;
	const EVP_MD *digest;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	algorithm_uc = estrdup(algorithm);
	php_crypto_hash_set_algorithm_name(getThis(), algorithm_uc, strlen(algorithm_uc) TSRMLS_CC);
	PHPC_THIS_FETCH(crypto_hash);

	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(Hash, HASH_ALGORITHM_NOT_FOUND), algorithm);
	} else {
		PHP_CRYPTO_HASH_ALG(PHPC_THIS) = digest;
	}

	efree(algorithm_uc);
}
/* }}} */

/* {{{ proto string Crypto\Hash::getAlgorithmName()
	Returns hash algorithm string */
PHP_CRYPTO_METHOD(Hash, getAlgorithmName)
{
	zval *algorithm;
	PHPC_READ_PROPERTY_RV_DECLARE;

	algorithm = PHP_CRYPTO_HASH_GET_ALGORITHM_NAME_EX(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
}
/* }}} */

/* {{{ proto void Crypto\Hash::update(string $data)
	Updates hash */
PHP_CRYPTO_METHOD(Hash, update)
{
	PHPC_THIS_DECLARE(crypto_hash);
	char *data;
	phpc_str_size_t data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_hash);
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
	int block_size;
	PHPC_THIS_DECLARE(crypto_hash);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_hash);

	/* find out block size */
	switch (PHPC_THIS->type) {
		case PHP_CRYPTO_HASH_TYPE_MD:
			block_size = EVP_MD_block_size(PHP_CRYPTO_HASH_ALG(PHPC_THIS));
			break;
		case PHP_CRYPTO_HASH_TYPE_HMAC:
			block_size = EVP_MD_block_size(PHP_CRYPTO_HMAC_ALG(PHPC_THIS));
			break;
#ifdef PHP_CRYPTO_HAS_CMAC
		case PHP_CRYPTO_HASH_TYPE_CMAC:
			block_size = EVP_CIPHER_block_size(PHP_CRYPTO_CMAC_ALG(PHPC_THIS));
			break;
#endif
		default:
			block_size = 0;
	}

	RETURN_LONG(block_size);
}

/* {{{ proto int Crypto\Hash::getSize()
	Returns hash size */
PHP_CRYPTO_METHOD(Hash, getSize)
{
	int hash_size;
	PHPC_THIS_DECLARE(crypto_hash);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(crypto_hash);

	/* find out block size */
	switch (PHPC_THIS->type) {
		case PHP_CRYPTO_HASH_TYPE_MD:
			hash_size = EVP_MD_size(PHP_CRYPTO_HASH_ALG(PHPC_THIS));
			break;
		case PHP_CRYPTO_HASH_TYPE_HMAC:
			hash_size = EVP_MD_size(PHP_CRYPTO_HMAC_ALG(PHPC_THIS));
			break;
#ifdef PHP_CRYPTO_HAS_CMAC
		case PHP_CRYPTO_HASH_TYPE_CMAC:
			hash_size = EVP_CIPHER_block_size(PHP_CRYPTO_CMAC_ALG(PHPC_THIS));
			break;
#endif
		default:
			hash_size = 0;
	}

	RETURN_LONG(hash_size);
}

/* {{{ proto Crypto\MAC::__construct(string $algorithm, string $key)
	Create a MAC (used by MAC subclasses - HMAC and CMAC) */
PHP_CRYPTO_METHOD(MAC, __construct)
{
	PHPC_THIS_DECLARE(crypto_hash);
	char *algorithm, *algorithm_uc, *key;
	phpc_str_size_t algorithm_len, key_len;
	int key_len_int;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
			&key, &key_len, &algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	algorithm_uc = estrdup(algorithm);
	algorithm_len = strlen(algorithm_uc);
	php_crypto_hash_set_algorithm_name(getThis(), algorithm_uc, algorithm_len TSRMLS_CC);
	PHPC_THIS_FETCH(crypto_hash);

	if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_HMAC) {
		const EVP_MD *digest = EVP_get_digestbyname(algorithm_uc);
		if (!digest) {
			goto php_crypto_mac_alg_not_found;
		}
		PHP_CRYPTO_HMAC_ALG(PHPC_THIS) = digest;
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC algorithm uses a cipher algorithm */
	else if (PHPC_THIS->type == PHP_CRYPTO_HASH_TYPE_CMAC) {
		const EVP_CIPHER *cipher = php_crypto_get_cipher_algorithm(algorithm_uc, algorithm_len);
		if (!cipher) {
			goto php_crypto_mac_alg_not_found;
		}
		if (key_len != EVP_CIPHER_block_size(cipher)) {
			php_crypto_error(PHP_CRYPTO_ERROR_ARGS(MAC, KEY_LENGTH_INVALID));
			efree(algorithm_uc);
			return;
		}
		PHP_CRYPTO_CMAC_ALG(PHPC_THIS) = cipher;
	}
#endif

	efree(algorithm_uc);

	/* check key length overflow */
	if (php_crypto_str_size_to_int(key_len, &key_len_int) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(MAC, KEY_LENGTH_INVALID));
		return;
	}

	PHPC_THIS->key = emalloc(key_len + 1);
	memcpy(PHPC_THIS->key, key, key_len);
	PHPC_THIS->key[key_len] = '\0';
	PHPC_THIS->key_len = key_len_int;
	return;

php_crypto_mac_alg_not_found:
	php_crypto_error_ex(PHP_CRYPTO_ERROR_ARGS(MAC, MAC_ALGORITHM_NOT_FOUND), algorithm);
	efree(algorithm_uc);
}
