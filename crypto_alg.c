/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2013-2015 Jakub Zelenka                                |
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
#include "php_crypto_alg.h"
#include "zend_exceptions.h"

#include <openssl/evp.h>

PHP_CRYPTO_EXCEPTION_DEFINE(Algorithm)

PHP_CRYPTO_EXCEPTION_DEFINE(Hash)
PHP_CRYPTO_ERROR_INFO_BEGIN(Hash)
PHP_CRYPTO_ERROR_INFO_ENTRY(ALGORITHM_NOT_FOUND, "Hash algorithm '%s' not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_NOT_FOUND, "Hash static method '%s' not found")
PHP_CRYPTO_ERROR_INFO_ENTRY(STATIC_METHOD_TOO_MANY_ARGS, "Hash static method %s can accept max one argument")
PHP_CRYPTO_ERROR_INFO_ENTRY(INIT_FAILED, "Initialization of hash failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(UPDATE_FAILED, "Updating of hash context failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(DIGEST_FAILED, "Creating of hash digest failed")
PHP_CRYPTO_ERROR_INFO_ENTRY(INPUT_DATA_LENGTH_HIGH, "Hashed message length can't exceed max integer length")
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

static const zend_function_entry php_crypto_algorithm_object_methods[] = {
	PHP_CRYPTO_ME(Algorithm, __construct,       arginfo_crypto_algorithm,      ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Algorithm, getAlgorithmName,  NULL,                          ZEND_ACC_PUBLIC)
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

/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
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
	PHPC_READ_PROPERTY(php_crypto_algorithm_ce, this_object, \
		"algorithm", sizeof("algorithm")-1, 1)

#define PHP_CRYPTO_GET_ALGORITHM_NAME(this_object) \
	Z_STRVAL_P(PHP_CRYPTO_GET_ALGORITHM_NAME_EX(this_object))

/* {{{ crypto_alg free object handler */
PHPC_OBJ_HANDLER_FREE(crypto_alg)
{
	PHPC_OBJ_HANDLER_FREE_INIT(crypto_alg);

	if (PHPC_THIS->type == PHP_CRYPTO_ALG_HASH) {
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

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}
/* }}} */

/* {{{ crypto_alg create_ex object helper */
PHPC_OBJ_HANDLER_CREATE_EX(crypto_alg)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(crypto_alg);

	if (PHPC_CLASS_TYPE == php_crypto_hash_ce) {
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

	if (PHPC_THAT->type == PHP_CRYPTO_ALG_HASH) {
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

	/* HashException registration */
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, Hash,  Algorithm);
	PHP_CRYPTO_ERROR_INFO_REGISTER(Hash);

	/* Hash class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Hash), php_crypto_hash_object_methods);
	php_crypto_hash_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_algorithm_ce, NULL);

	/* HMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(HMAC), NULL);
	php_crypto_hmac_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_hash_ce, NULL);

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(CMAC), NULL);
	php_crypto_cmac_ce = PHPC_CLASS_REGISTER_EX(ce, php_crypto_hash_ce, NULL);
#endif

	return SUCCESS;
}
/* }}} */

/* ALGORITHM METHODS */

/* do all parameter structure */
typedef struct {
	zend_bool aliases;
	char *prefix;
	phpc_str_size_t prefix_len;
	zval *return_value;
} php_crypto_do_all_algorithms_param;

/* {{{ php_crypto_do_all_algorithms */
static void php_crypto_do_all_algorithms(const OBJ_NAME *name, void *arg)
{
	php_crypto_do_all_algorithms_param *pp = (php_crypto_do_all_algorithms_param *) arg;
	if ((pp->aliases || name->alias == 0) &&
			(!pp->prefix || !strncmp(name->name, pp->prefix, pp->prefix_len))) {
		PHPC_ARRAY_ADD_NEXT_INDEX_CSTR(pp->return_value, (char *) name->name);
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
	zval *algorithm;
	PHPC_READ_PROPERTY_RV_DECLARE;

	algorithm = PHP_CRYPTO_GET_ALGORITHM_NAME_EX(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
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
		char *data, phpc_str_size_t data_str_size TSRMLS_DC)
{
	int data_len;

	/* check string length overflow */
	if (php_crypto_str_size_to_int(data_str_size, &data_len) == FAILURE) {
		php_crypto_error(PHP_CRYPTO_ERROR_ARGS(Hash, INPUT_DATA_LENGTH_HIGH));
		return FAILURE;
	}

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
