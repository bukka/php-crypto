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
#include "php_crypto_alg.h"
#include "zend_exceptions.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_smart_str.h"

#include <openssl/evp.h>


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
	PHP_CRYPTO_FE_END
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
	PHP_CRYPTO_FE_END
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
	PHP_CRYPTO_FE_END
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
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(GCM, 1, EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_SET_TAG, EVP_CTRL_GCM_GET_TAG)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(GCM)
#endif
#ifdef EVP_CIPH_CCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(CCM, 1, EVP_CTRL_CCM_SET_IVLEN, EVP_CTRL_CCM_SET_TAG, EVP_CTRL_CCM_GET_TAG)
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

/* object handlers */
static zend_object_handlers php_crypto_algorithm_object_handlers;

/* algorithme name getter macros */
#define PHP_CRYPTO_GET_ALGORITHM_NAME_EX(this_object) \
	zend_read_property(php_crypto_algorithm_ce, this_object, "algorithm", sizeof("algorithm")-1, 1 TSRMLS_CC)

#define PHP_CRYPTO_GET_ALGORITHM_NAME(this_object) \
	Z_STRVAL_P(PHP_CRYPTO_GET_ALGORITHM_NAME_EX(this_object))

/* {{{ php_crypto_algorithm_object_dtor */
static void php_crypto_algorithm_object_dtor(void *object, zend_object_handle handle TSRMLS_DC)
{
	zend_objects_destroy_object(object, handle TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_algorithm_object_free */
static void php_crypto_algorithm_object_free(zend_object *object TSRMLS_DC)
{
	php_crypto_algorithm_object *intern = (php_crypto_algorithm_object *) object;

	if (intern->type == PHP_CRYPTO_ALG_CIPHER) {
		EVP_CIPHER_CTX_cleanup(PHP_CRYPTO_CIPHER_CTX(intern));
		efree(PHP_CRYPTO_CIPHER_CTX(intern));
	} else if (intern->type == PHP_CRYPTO_ALG_HASH) {
		EVP_MD_CTX_cleanup(PHP_CRYPTO_HASH_CTX(intern));
		efree(PHP_CRYPTO_HASH_CTX(intern));
	} else if (intern->type == PHP_CRYPTO_ALG_HMAC) {
		HMAC_CTX_cleanup(PHP_CRYPTO_HMAC_CTX(intern));
		efree(PHP_CRYPTO_HMAC_CTX(intern));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (intern->type == PHP_CRYPTO_ALG_CMAC) {
		CMAC_CTX_cleanup(PHP_CRYPTO_CMAC_CTX(intern));
		efree(PHP_CRYPTO_CMAC_CTX(intern));
	}
#endif

	if (PHP_CRYPTO_CIPHER_AAD(intern)) {
		efree(PHP_CRYPTO_CIPHER_AAD(intern));
	}
	if (PHP_CRYPTO_CIPHER_TAG(intern)) {
		efree(PHP_CRYPTO_CIPHER_TAG(intern));
	}

	zend_object_std_dtor(&intern->zo TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ php_crypto_algorithm_object_create_ex */
static zend_object_value php_crypto_algorithm_object_create_ex(zend_class_entry *class_type, php_crypto_algorithm_object **ptr TSRMLS_DC)
{
	zend_object_value retval;
	php_crypto_algorithm_object *intern;

	/* Allocate memory for it */
	intern = (php_crypto_algorithm_object *) emalloc(sizeof(php_crypto_algorithm_object));
	memset(intern, 0, sizeof(php_crypto_algorithm_object));
	if (ptr) {
		*ptr = intern;
	}
	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	PHP_CRYPTO_OBJECT_PROPERTIES_INIT(&intern->zo, class_type);

	if (class_type == php_crypto_cipher_ce) {
		intern->type = PHP_CRYPTO_ALG_CIPHER;
		PHP_CRYPTO_CIPHER_CTX(intern) = (EVP_CIPHER_CTX *) emalloc(sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(PHP_CRYPTO_CIPHER_CTX(intern));
	} else if (class_type == php_crypto_hash_ce) {
		intern->type = PHP_CRYPTO_ALG_HASH;
		PHP_CRYPTO_HASH_CTX(intern) = (EVP_MD_CTX *) emalloc(sizeof(EVP_MD_CTX));
		EVP_MD_CTX_init(PHP_CRYPTO_HASH_CTX(intern));
	} else if (class_type == php_crypto_hmac_ce) {
		intern->type = PHP_CRYPTO_ALG_HMAC;
		PHP_CRYPTO_HMAC_CTX(intern) = (HMAC_CTX *) emalloc(sizeof(HMAC_CTX));
		HMAC_CTX_init(PHP_CRYPTO_HMAC_CTX(intern));
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (class_type == php_crypto_cmac_ce) {
		intern->type = PHP_CRYPTO_ALG_CMAC;
		PHP_CRYPTO_CMAC_CTX(intern) = (CMAC_CTX *) emalloc(sizeof(CMAC_CTX));
		CMAC_CTX_init(PHP_CRYPTO_CMAC_CTX(intern));
	}
#endif
	else {
		intern->type = PHP_CRYPTO_ALG_NONE;
	}

	retval.handlers = &php_crypto_algorithm_object_handlers;
	retval.handle = zend_objects_store_put(
		intern,
		(zend_objects_store_dtor_t) php_crypto_algorithm_object_dtor,
		(zend_objects_free_object_storage_t) php_crypto_algorithm_object_free,
		NULL TSRMLS_CC);

	return retval;
}
/* }}} */

/* {{{ php_crypto_algorithm_object_create */
static zend_object_value php_crypto_algorithm_object_create(zend_class_entry *class_type TSRMLS_DC)
{
	return php_crypto_algorithm_object_create_ex(class_type, NULL TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_algorith_object_clone */
zend_object_value php_crypto_algorithm_object_clone(zval *this_ptr TSRMLS_DC)
{
	int copy_success;
	php_crypto_algorithm_object *new_obj = NULL;
	php_crypto_algorithm_object *old_obj = (php_crypto_algorithm_object *) zend_object_store_get_object(this_ptr TSRMLS_CC);
	zend_object_value new_ov = php_crypto_algorithm_object_create_ex(old_obj->zo.ce, &new_obj TSRMLS_CC);

	zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);
	new_obj->status = old_obj->status;
	new_obj->type = old_obj->type;

	if (new_obj->type == PHP_CRYPTO_ALG_CIPHER) {
#ifdef PHP_CRYPTO_HAS_CIPHER_CTX_COPY
		copy_success = EVP_CIPHER_CTX_copy(PHP_CRYPTO_CIPHER_CTX(new_obj), PHP_CRYPTO_CIPHER_CTX(old_obj));
#else
		memcpy(PHP_CRYPTO_CIPHER_CTX(new_obj), PHP_CRYPTO_CIPHER_CTX(old_obj), sizeof *(PHP_CRYPTO_CIPHER_CTX(new_obj)));
		copy_success = 1;
		if (PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher_data && PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher->ctx_size) {
			PHP_CRYPTO_CIPHER_CTX(new_obj)->cipher_data = OPENSSL_malloc(PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher->ctx_size);
			if (!PHP_CRYPTO_CIPHER_CTX(new_obj)->cipher_data) {
				copy_success = 0;
			}
			memcpy(PHP_CRYPTO_CIPHER_CTX(new_obj)->cipher_data, PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher_data, PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher->ctx_size);
		}
#endif
		PHP_CRYPTO_CIPHER_ALG(new_obj) = PHP_CRYPTO_CIPHER_CTX(old_obj)->cipher;
	} else if (new_obj->type == PHP_CRYPTO_ALG_HASH) {
		copy_success = EVP_MD_CTX_copy(PHP_CRYPTO_HASH_CTX(new_obj), PHP_CRYPTO_HASH_CTX(old_obj));
		PHP_CRYPTO_HASH_ALG(new_obj) = PHP_CRYPTO_HASH_CTX(old_obj)->digest;
	} else if (new_obj->type == PHP_CRYPTO_ALG_HMAC) {
#ifdef PHP_CRYPTO_HAS_CIPHER_CTX_COPY
		copy_success = HMAC_CTX_copy(PHP_CRYPTO_HMAC_CTX(new_obj), PHP_CRYPTO_HMAC_CTX(old_obj));
#else
		copy_success = 0;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(new_obj)->i_ctx, &PHP_CRYPTO_HMAC_CTX(old_obj)->i_ctx))
			goto copy_end;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(new_obj)->o_ctx, &PHP_CRYPTO_HMAC_CTX(old_obj)->o_ctx))
			goto copy_end;
		if (!EVP_MD_CTX_copy(&PHP_CRYPTO_HMAC_CTX(new_obj)->md_ctx, &PHP_CRYPTO_HMAC_CTX(old_obj)->md_ctx))
			goto copy_end;
		memcpy(PHP_CRYPTO_HMAC_CTX(new_obj)->key, PHP_CRYPTO_HMAC_CTX(old_obj)->key, HMAC_MAX_MD_CBLOCK);
		PHP_CRYPTO_HMAC_CTX(new_obj)->key_length = PHP_CRYPTO_HMAC_CTX(old_obj)->key_length;
		PHP_CRYPTO_HMAC_CTX(new_obj)->md = PHP_CRYPTO_HMAC_CTX(old_obj)->md;
		copy_success = 1;
#endif
	}
#ifdef PHP_CRYPTO_HAS_CMAC
	else if (new_obj->type == PHP_CRYPTO_ALG_CMAC) {
		copy_success = CMAC_CTX_copy(PHP_CRYPTO_CMAC_CTX(new_obj), PHP_CRYPTO_CMAC_CTX(old_obj));
	}
#endif
	else {
		copy_success = 0;
	}

copy_end:
	if (!copy_success) {
		php_error(E_ERROR, "Cloning of Algorithm object failed");
	}
	return new_ov;
}
/* }}} */


#define PHP_CRYPTO_DECLARE_ALG_E_CONST(aconst) \
	zend_declare_class_constant_long(php_crypto_algorithm_exception_ce, #aconst, sizeof(#aconst)-1, PHP_CRYPTO_ALG_E(aconst) TSRMLS_CC)

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_alg)
{
	zend_class_entry ce;
	const php_crypto_cipher_mode *mode;

	/* Algorithm class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Algorithm), php_crypto_algorithm_object_methods);
	ce.create_object = php_crypto_algorithm_object_create;
	memcpy(&php_crypto_algorithm_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_crypto_algorithm_object_handlers.clone_obj = php_crypto_algorithm_object_clone;
	php_crypto_algorithm_ce = zend_register_internal_class(&ce TSRMLS_CC);
	zend_declare_property_null(php_crypto_algorithm_ce, "algorithm", sizeof("algorithm")-1, ZEND_ACC_PROTECTED TSRMLS_CC);

	/* Algorithm Exception class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(AlgorithmException), NULL);
	php_crypto_algorithm_exception_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	/* Declare AlorithmException class constants for error codes */
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_MODE_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_MODE_NOT_AVAILABLE);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_AUTHENTICATION_NOT_SUPPORTED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_AUTHENTICATION_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_KEY_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_IV_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_AAD_SETTER_FLOW);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_AAD_SETTER_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_GETTER_FLOW);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_SETTER_FLOW);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_GETTER_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_SETTER_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_LENGTH_UNDER);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_LENGTH_OVER);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_TAG_VARIFY_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_INIT_ALG_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_INIT_CTX_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_UPDATE_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_FINISH_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_INIT_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_FINISH_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_INIT_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_FINISH_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(HASH_ALGORITHM_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(HASH_STATIC_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(HASH_INIT_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(HASH_UPDATE_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(HASH_DIGEST_FAILED);

	/* Cipher class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Cipher), php_crypto_cipher_object_methods);
	php_crypto_cipher_ce = zend_register_internal_class_ex(&ce, php_crypto_algorithm_ce, NULL TSRMLS_CC);
	/* Cipher constants for modes */
	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		zend_declare_class_constant_long(php_crypto_cipher_ce, mode->constant, strlen(mode->constant), mode->value TSRMLS_CC);
	}

	/* Hash class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Hash), php_crypto_hash_object_methods);
	php_crypto_hash_ce = zend_register_internal_class_ex(&ce, php_crypto_algorithm_ce, NULL TSRMLS_CC);

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
	if ((pp->aliases || name->alias == 0) && (!pp->prefix || !strncmp(name->name, pp->prefix, pp->prefix_len))) {
		add_next_index_string(pp->return_value, (char *) name->name, 1);
	}
}
/* }}} */

/* {{{ php_crypto_get_algorithms */
static void php_crypto_get_algorithms(INTERNAL_FUNCTION_PARAMETERS, int type)
{
	php_crypto_do_all_algorithms_param param = { 0, NULL, 0, return_value };
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|bs", &param.aliases, &param.prefix, &param.prefix_len) == FAILURE) {
		return;
	}
	array_init(return_value);
	OBJ_NAME_do_all_sorted(type, php_crypto_do_all_algorithms, &param);
}
/* }}} */

/* {{{ php_crypto_get_algorithm_object_ex */
static inline void php_crypto_set_algorithm_name(zval *object, char *algorithm, int algorithm_len TSRMLS_DC)
{
	php_strtoupper(algorithm, algorithm_len);
	zend_update_property_stringl(php_crypto_algorithm_ce, object, "algorithm", sizeof("algorithm")-1, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ proto Crypto\Algorithm::__construct(string $algorithm)
   Algorithm constructor */
PHP_CRYPTO_METHOD(Algorithm, __construct)
{
	char *algorithm;
	int algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &algorithm, &algorithm_len) == FAILURE) {
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
		zval *object, char *algorithm, int algorithm_len, zval *pz_mode, zval *pz_key_size TSRMLS_DC)
{
	const EVP_CIPHER *cipher;
	smart_str alg_buf = {0};

	if (!pz_mode || Z_TYPE_P(pz_mode) == IS_NULL) {
		cipher = php_crypto_get_cipher_algorithm(algorithm, algorithm_len);
		if (!cipher) {
			PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher '%s' algorithm not found", algorithm);
		} else if (object) {
			php_crypto_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
		}
		return cipher;
	}

	smart_str_appendl(&alg_buf, algorithm, algorithm_len);
	smart_str_appendc(&alg_buf, '-');

	/* copy key size if available */
	if (pz_key_size && Z_TYPE_P(pz_key_size) != IS_NULL) {
		if (Z_TYPE_P(pz_key_size) == IS_STRING) {
			smart_str_appendl(&alg_buf, Z_STRVAL_P(pz_key_size), Z_STRLEN_P(pz_key_size));
		} else {
			zval z_key_size = *pz_key_size;
			zval_copy_ctor(&z_key_size);
			convert_to_string(&z_key_size);
			smart_str_appendl(&alg_buf, Z_STRVAL(z_key_size), Z_STRLEN(z_key_size));
			smart_str_appendc(&alg_buf, '-');
			zval_dtor(&z_key_size);
		}
	}

	/* copy mode */
	if (Z_TYPE_P(pz_mode) == IS_LONG) {
		const php_crypto_cipher_mode *mode = php_crypto_get_cipher_mode_ex(Z_LVAL_P(pz_mode));
		if (!mode) {
			PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_MODE_NOT_FOUND, "Cipher mode with integer value %d does not exist", Z_LVAL_P(pz_mode));
			smart_str_free(&alg_buf);
			return NULL;
		}
		if (mode->value == PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED) {
			PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_MODE_NOT_AVAILABLE, "Cipher mode %s is not available in installed OpenSSL library", mode->name);
			smart_str_free(&alg_buf);
			return NULL;
		}
		smart_str_appendl(&alg_buf, mode->name, PHP_CRYPTO_CIPHER_MODE_LEN);
	} else if (Z_TYPE_P(pz_mode) == IS_STRING) {
		smart_str_appendl(&alg_buf, Z_STRVAL_P(pz_mode), Z_STRLEN_P(pz_mode));
	} else {
		zval z_mode = *pz_mode;
		zval_copy_ctor(&z_mode);
		convert_to_string(&z_mode);
		smart_str_appendl(&alg_buf, Z_STRVAL(z_mode), Z_STRLEN(z_mode));
		zval_dtor(&z_mode);
	}

	smart_str_0(&alg_buf);
	cipher = php_crypto_get_cipher_algorithm(alg_buf.c, alg_buf.len);
	if (!cipher) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher '%s' algorithm not found", alg_buf.c);
	} else if (object) {
		php_crypto_set_algorithm_name(object, alg_buf.c, alg_buf.len TSRMLS_CC);
	}
	smart_str_free(&alg_buf);
	return cipher;
}
/* }}} */

/* {{{ php_crypto_get_cipher_algorithm_from_params_ex */
PHP_CRYPTO_API const EVP_CIPHER *php_crypto_get_cipher_algorithm_from_params(
		char *algorithm, int algorithm_len, zval *pz_mode, zval *pz_key_size TSRMLS_DC)
{
	return php_crypto_get_cipher_algorithm_from_params_ex(NULL, algorithm, algorithm_len, pz_mode, pz_key_size TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_ex */
static int php_crypto_set_cipher_algorithm_ex(php_crypto_algorithm_object *intern, char *algorithm, int algorithm_len TSRMLS_DC)
{
	const EVP_CIPHER *cipher = php_crypto_get_cipher_algorithm(algorithm, algorithm_len);
	if (!cipher) {
		return FAILURE;
	}
	PHP_CRYPTO_CIPHER_ALG(intern) = cipher;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm */
static int php_crypto_set_cipher_algorithm(zval *object, char *algorithm, int algorithm_len TSRMLS_DC)
{
	php_crypto_algorithm_object *intern = (php_crypto_algorithm_object *) zend_object_store_get_object(object TSRMLS_CC);
	php_crypto_set_algorithm_name(object, algorithm, algorithm_len TSRMLS_CC);
	return php_crypto_set_cipher_algorithm_ex(intern, algorithm, algorithm_len TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm_from_params */
static int php_crypto_set_cipher_algorithm_from_params(
		zval *object, char *algorithm, int algorithm_len, zval *pz_mode, zval *pz_key_size TSRMLS_DC)
{
	php_crypto_algorithm_object *intern = (php_crypto_algorithm_object *) zend_object_store_get_object(object TSRMLS_CC);
	const EVP_CIPHER *cipher = php_crypto_get_cipher_algorithm_from_params_ex(
			object, algorithm, algorithm_len, pz_mode, pz_key_size TSRMLS_CC);
	
	if (!cipher) {
		return FAILURE;
	}
	
	PHP_CRYPTO_CIPHER_ALG(intern) = cipher;
	return SUCCESS;
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
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_MODE_NOT_FOUND, "Cipher mode not found");
		return FAILURE;
	}
	if (!mode->auth_enc) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_AUTHENTICATION_NOT_SUPPORTED,
			"The authentication is not supported for %s cipher mode", mode->name);
		return FAILURE;
	}
	return SUCCESS;
}

/* {{{ php_crypto_cipher_is_mode_authenticated */
static int php_crypto_cipher_is_mode_authenticated(php_crypto_algorithm_object *intern TSRMLS_DC)
{
	return php_crypto_cipher_is_mode_authenticated_ex(php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern)) TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_cipher_set_tag */
static int php_crypto_cipher_set_tag(php_crypto_algorithm_object *intern, const php_crypto_cipher_mode *mode, unsigned char *tag, int tag_len TSRMLS_DC)
{
	if (!tag) {
		return SUCCESS;
	}
	if (!EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(intern), mode->auth_set_tag_flag, tag_len, tag)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_SETTER_FAILED, "Tag setter failed");
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_tag_len */
static int php_crypto_cipher_check_tag_len(long tag_len TSRMLS_DC)
{
	if (tag_len < 4) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_LENGTH_UNDER, "Tag length can't be lower than 32 bits (4 characters)");
		return FAILURE;
	}
	if (tag_len > 16) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_LENGTH_OVER, "Tag length can't exceed 128 bits (16 characters)");
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_key_len */
static int php_crypto_cipher_check_key_len(zval *zobject, php_crypto_algorithm_object *intern, int key_len TSRMLS_DC)
{
	int alg_key_len = EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(intern));

	if (key_len != alg_key_len && !EVP_CIPHER_CTX_set_key_length(PHP_CRYPTO_CIPHER_CTX(intern), key_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_KEY_LENGTH,
			"Invalid length of key for cipher '%s' algorithm (required length: %d)",
			PHP_CRYPTO_GET_ALGORITHM_NAME(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_iv_len */
static int php_crypto_cipher_check_iv_len(zval *zobject, php_crypto_algorithm_object *intern, const php_crypto_cipher_mode *mode, int iv_len TSRMLS_DC)
{
	int alg_iv_len = EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(intern));
	if (iv_len == alg_iv_len) {
		return SUCCESS;
	}

	if (!mode->auth_enc || !EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(intern), mode->auth_ivlen_flag, iv_len, NULL)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_IV_LENGTH,
			"Invalid length of initial vector (IV) for cipher '%s' algorithm (required length: %d)",
			PHP_CRYPTO_GET_ALGORITHM_NAME(zobject), alg_iv_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_init_ex */
static php_crypto_algorithm_object *php_crypto_cipher_init_ex(zval *zobject, char *key, int key_len, char *iv, int iv_len, int enc TSRMLS_DC)
{
	php_crypto_algorithm_object *intern = (php_crypto_algorithm_object *) zend_object_store_get_object(zobject TSRMLS_CC);
	const php_crypto_cipher_mode *mode;

	/* check algorithm status */
	if (enc && PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_INIT_STATUS, "Cipher object is already used for decryption");
		return NULL;
	} else if (!enc && PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_INIT_STATUS, "Cipher object is already used for encryption");
		return NULL;
	}

	/* initialize encryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(intern), PHP_CRYPTO_CIPHER_ALG(intern), NULL, NULL, NULL, enc)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_INIT_ALG_FAILED, "Initialization of cipher algorithm failed");
		return NULL;
	}

	/* check key length */
	if (php_crypto_cipher_check_key_len(zobject, intern, key_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* get mode */
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));

	/* check initialization vector length */
	if (php_crypto_cipher_check_iv_len(zobject, intern, mode, iv_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* initialize encryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(intern), NULL, NULL, (unsigned char *) key, (unsigned char *) iv, enc)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_INIT_CTX_FAILED, "Initialization of cipher context failed");
		return NULL;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(intern, enc, INIT);

	if (mode->auth_enc && !enc &&
			php_crypto_cipher_set_tag(intern, mode, PHP_CRYPTO_CIPHER_TAG(intern), PHP_CRYPTO_CIPHER_TAG_LEN(intern) TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	return intern;
}
/* }}} */

/* {{{ php_crypto_cipher_init */
static inline void php_crypto_cipher_init(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	char *key, *iv = NULL;
	int key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	php_crypto_cipher_init_ex(getThis(), key, key_len, iv, iv_len, enc TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_cipher_write_aad */
static inline int php_crypto_cipher_write_aad(php_crypto_algorithm_object *intern TSRMLS_DC)
{
	int outlen, ret;

	if (PHP_CRYPTO_CIPHER_AAD(intern)) {
		ret = EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(intern), NULL, &outlen, PHP_CRYPTO_CIPHER_AAD(intern), PHP_CRYPTO_CIPHER_AAD_LEN(intern));
	} else {
		unsigned char buf[4];
		ret = EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(intern), NULL, &outlen, buf, 0);
	}

	if (!ret) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_AAD_SETTER_FAILED, "AAD setter failed");
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_update */
static inline void php_crypto_cipher_update(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	php_crypto_algorithm_object *intern;
	const php_crypto_cipher_mode *mode;
	unsigned char *outbuf;
	char *data;
	int data_len, outbuf_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	/* check algorithm status */
	if (enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_UPDATE_STATUS, "Cipher object is not initialized for encryption");
		return;
	} else if (!enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_UPDATE_STATUS, "Cipher object is not initialized for decryption");
		return;
	}

	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));

	if (mode->auth_enc && !php_crypto_cipher_write_aad(intern TSRMLS_CC) == FAILURE) {
		return;
	}

	outbuf_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc(outbuf_len + 1);
	
	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(intern), outbuf, &outbuf_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_UPDATE_FAILED, "Updating of cipher failed");
		efree(outbuf);
		return;
	}
	PHP_CRYPTO_CIPHER_SET_STATUS(intern, enc, UPDATE);
	outbuf[outbuf_len] = 0;
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
}
/* }}} */

/* {{{ php_crypto_cipher_finish */
static inline void php_crypto_cipher_finish(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	php_crypto_algorithm_object *intern;
	unsigned char *outbuf;
	int outbuf_len;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	/* check algorithm status */
	if (enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_ENCRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINISH_STATUS, "Cipher object is not initialized for encryption");
		return;
	} else if (!enc && !PHP_CRYPTO_CIPHER_IS_INITIALIZED_FOR_DECRYPTION(intern)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_FINISH_STATUS, "Cipher object is not initialized for decryption");
		return;
	}

	outbuf_len = EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc(outbuf_len + 1);

	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(intern), outbuf, &outbuf_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_FINISH_FAILED, "Finalizing of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	PHP_CRYPTO_CIPHER_SET_STATUS(intern, enc, FINAL);
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
}
/* }}} */

/* {{{ php_crypto_cipher_crypt */
static inline void php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	php_crypto_algorithm_object *intern;
	const php_crypto_cipher_mode *mode;
	unsigned char *outbuf;
	char *data, *key, *iv = NULL;
	int outbuf_len, outbuf_update_len, outbuf_final_len, data_len, key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s", &data, &data_len, &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	intern = php_crypto_cipher_init_ex(getThis(), key, key_len, iv, iv_len, enc TSRMLS_CC);
	if (intern == NULL) {
		return;
	}

	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));

	if (mode->auth_enc && !php_crypto_cipher_write_aad(intern TSRMLS_CC) == FAILURE) {
		return;
	}

	outbuf_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc(outbuf_len + 1);

	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(intern), outbuf, &outbuf_update_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_UPDATE_FAILED, "Updating of cipher failed");
		efree(outbuf);
		return;
	}
	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(intern), outbuf + outbuf_update_len, &outbuf_final_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_FINISH_FAILED, "Finalizing of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf_len = outbuf_update_len + outbuf_final_len;
	outbuf[outbuf_len] = 0;
	PHP_CRYPTO_CIPHER_SET_STATUS(intern, enc, FINAL);
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
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
	int algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &algorithm, &algorithm_len) == FAILURE) {
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
	int algorithm_len, argc;
	zval **ppz_mode, **ppz_key_size, *args;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &algorithm, &algorithm_len, &args) == FAILURE) {
		return;
	}

	argc = zend_hash_num_elements(Z_ARRVAL_P(args));
	if (argc > 2) {
		zend_error(E_WARNING, "The static function %s can accept max two arguments", algorithm);
		RETURN_NULL();
	}

	object_init_ex(return_value, php_crypto_cipher_ce);

	if (argc == 0) {
		php_crypto_set_cipher_algorithm(return_value, algorithm, algorithm_len TSRMLS_CC);
		return;
	}

	zend_hash_internal_pointer_reset(Z_ARRVAL_P(args));
	zend_hash_get_current_data(Z_ARRVAL_P(args), (void **) &ppz_mode);
	if (argc == 1) {
		php_crypto_set_cipher_algorithm_from_params(return_value, algorithm, algorithm_len, *ppz_mode, NULL TSRMLS_CC);
		return;
	}
	zend_hash_move_forward(Z_ARRVAL_P(args));
	zend_hash_get_current_data(Z_ARRVAL_P(args), (void **) &ppz_key_size);
	php_crypto_set_cipher_algorithm_from_params(return_value, algorithm, algorithm_len, *ppz_mode, *ppz_key_size TSRMLS_CC);
}
/* }}} */

/* {{{ proto Crypto\Cipher::__construct(string $algorithm, int $mode = NULL, string $key_size = NULL)
   Cipher constructor */
PHP_CRYPTO_METHOD(Cipher, __construct)
{
	char *algorithm;
	int algorithm_len;
	zval *mode = NULL, *key_size = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zz", &algorithm, &algorithm_len, &mode, &key_size) == FAILURE) {
		return;
	}
	php_crypto_set_cipher_algorithm_from_params(getThis(), algorithm, algorithm_len, mode, key_size TSRMLS_CC);
}
/* }}} */

/* {{{ proto void Crypto\Cipher::encryptInit(string $key, string $iv = null)
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
   Enrypts text to ciphertext */
PHP_CRYPTO_METHOD(Cipher, encrypt)
{
	php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/* {{{ proto void Crypto\Cipher::decryptInit(string $key, string $iv = null)
   Initializes cipher decription */
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
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern)));
}

/* {{{ proto int Crypto\Cipher::getKeyLength()
   Returns cipher key length */
PHP_CRYPTO_METHOD(Cipher, getKeyLength)
{
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(intern)));
}

/* {{{ proto int Crypto\Cipher::getIVLength()
   Returns cipher IV length */
PHP_CRYPTO_METHOD(Cipher, getIVLength)
{
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(intern)));
}

/* {{{ proto int Crypto\Cipher::getMode()
   Returns cipher mode */
PHP_CRYPTO_METHOD(Cipher, getMode)
{
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));
}
/* }}} */

/* {{{ proto string Crypto\Cipher::getTag(int $tag_size)
   Returns authentication tag */
PHP_CRYPTO_METHOD(Cipher, getTag)
{
	php_crypto_algorithm_object *intern;
	const php_crypto_cipher_mode *mode;
	long tag_len;
	unsigned char *tag;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &tag_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE || php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		return;
	}

	if (intern->status != PHP_CRYPTO_ALG_STATUS_ENCRYPT_FINAL) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_GETTER_FLOW, "Tag getter has to be called after encryption");
		return;
	}

	tag = emalloc(tag_len + 1);
	tag[tag_len] = 0;

	if (!EVP_CIPHER_CTX_ctrl(PHP_CRYPTO_CIPHER_CTX(intern), mode->auth_get_tag_flag, tag_len, tag)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_GETTER_FAILED, "Tag getter failed");
		return;
	}

	RETURN_STRINGL((char *) tag, tag_len, 0);
}
/* }}} */

/* {{{ proto void Crypto\Cipher::setTag(string $tag)
   Sets authentication tag */
PHP_CRYPTO_METHOD(Cipher, setTag)
{
	php_crypto_algorithm_object *intern;
	const php_crypto_cipher_mode *mode;
	char *tag;
	int tag_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &tag, &tag_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	mode = php_crypto_get_cipher_mode_ex(PHP_CRYPTO_CIPHER_MODE_VALUE(intern));
	if (php_crypto_cipher_is_mode_authenticated_ex(mode TSRMLS_CC) == FAILURE || php_crypto_cipher_check_tag_len(tag_len TSRMLS_CC) == FAILURE) {
		return;
	}

	if (intern->status == PHP_CRYPTO_ALG_STATUS_CLEAR) {
		if (!PHP_CRYPTO_CIPHER_TAG(intern)) {
			PHP_CRYPTO_CIPHER_TAG(intern) = emalloc(tag_len + 1);
		} else if (PHP_CRYPTO_CIPHER_TAG_LEN(intern) < tag_len) {
			PHP_CRYPTO_CIPHER_TAG(intern) = erealloc(PHP_CRYPTO_CIPHER_TAG(intern), tag_len + 1);
		}
		memcpy(PHP_CRYPTO_CIPHER_TAG(intern), tag, tag_len + 1);
		PHP_CRYPTO_CIPHER_TAG_LEN(intern) = tag_len;
	} else if (intern->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT) {
		php_crypto_cipher_set_tag(intern, mode, (unsigned char *) tag, tag_len TSRMLS_CC);
	} else {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_TAG_SETTER_FLOW, "Tag setter has to be called before decryption");
	}
}
/* }}} */

/* {{{ proto void Crypto\Cipher::setAAD(string $aad)
   Sets additional application data for authenticated encryption */
PHP_CRYPTO_METHOD(Cipher, setAAD)
{
	php_crypto_algorithm_object *intern;
	char *aad;
	int aad_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &aad, &aad_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	if (php_crypto_cipher_is_mode_authenticated(intern TSRMLS_CC) == FAILURE) {
		return;
	}

	if (intern->status == PHP_CRYPTO_ALG_STATUS_CLEAR ||
			intern->status == PHP_CRYPTO_ALG_STATUS_ENCRYPT_INIT ||
			intern->status == PHP_CRYPTO_ALG_STATUS_DECRYPT_INIT) {
		if (!PHP_CRYPTO_CIPHER_AAD(intern)) {
			PHP_CRYPTO_CIPHER_AAD(intern) = emalloc(aad_len + 1);
		} else if (PHP_CRYPTO_CIPHER_AAD_LEN(intern) < aad_len) {
			PHP_CRYPTO_CIPHER_AAD(intern) = erealloc(PHP_CRYPTO_CIPHER_AAD(intern), aad_len + 1);
		}
		memcpy(PHP_CRYPTO_CIPHER_AAD(intern), aad, aad_len + 1);
		PHP_CRYPTO_CIPHER_AAD_LEN(intern) = aad_len;
	} else {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_AAD_SETTER_FLOW, "AAD setter has to be called before encryption or decryption");
	}
}
/* }}} */

/* HASH METHODS */

/* {{{ php_crypto_hash_init */
static inline int php_crypto_hash_init(php_crypto_algorithm_object *intern TSRMLS_DC)
{
	/* initialize hash */
	if (!EVP_DigestInit_ex(PHP_CRYPTO_HASH_CTX(intern), PHP_CRYPTO_HASH_ALG(intern), NULL)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(HASH_INIT_FAILED, "Initialization of hash failed");
		return FAILURE;
	}
	intern->status = PHP_CRYPTO_ALG_STATUS_HASH;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_update */
static inline int php_crypto_hash_update(php_crypto_algorithm_object *intern, char *data, int data_len TSRMLS_DC)
{
	/* check if hash is initialized and if it's not, then try to initialize */
	if (intern->status != PHP_CRYPTO_ALG_STATUS_HASH && php_crypto_hash_init(intern TSRMLS_CC) == FAILURE) {
		return FAILURE;
	}

	/* update hash context */
	if (!EVP_DigestUpdate(PHP_CRYPTO_HASH_CTX(intern), data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(HASH_UPDATE_FAILED, "Updating of hash failed");
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_hash_bin2hex */
static inline void php_crypto_hash_bin2hex(char *out, const unsigned char *in, unsigned in_len)
{
	static const char hexits[17] = "0123456789abcdef";
	unsigned i;
	for(i = 0; i < in_len; i++) {
		out[i * 2]       = hexits[in[i] >> 4];
		out[(i * 2) + 1] = hexits[in[i] &  0x0F];
	}
}
/* }}} */

/* {{{ php_crypto_hash_finish */
static inline char *php_crypto_hash_finish(php_crypto_algorithm_object *intern, int encode_to_hex TSRMLS_DC)
{
	unsigned char hash_value[EVP_MAX_MD_SIZE+1];
	unsigned hash_len;

	/* check if hash is initialized and if it's not, then try to initialize */
	if (intern->status != PHP_CRYPTO_ALG_STATUS_HASH && php_crypto_hash_init(intern TSRMLS_CC) == FAILURE) {
		return NULL;
	}

	/* finalize hash context */
	if (!EVP_DigestFinal(PHP_CRYPTO_HASH_CTX(intern), hash_value, &hash_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(HASH_DIGEST_FAILED, "Finalizing of hash failed");
		return NULL;
	}
	hash_value[hash_len] = 0;
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;

	if (encode_to_hex) {
		int retval_len = hash_len * 2 + 1;
		char *retval = (char *) emalloc(retval_len);
		php_crypto_hash_bin2hex(retval, hash_value, hash_len);
		retval[retval_len-1] = 0;
		return retval;
	}
	return estrdup((char *) hash_value);
}
/* }}} */

/* {{{ php_crypto_hash_digest */
static inline void php_crypto_hash_digest(INTERNAL_FUNCTION_PARAMETERS, int encode_to_hex)
{
	php_crypto_algorithm_object *intern;
	char *hash;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	hash = php_crypto_hash_finish(intern, encode_to_hex TSRMLS_CC);
	if (hash) {
		RETURN_STRING(hash, 0);
	}
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
	int algorithm_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &algorithm, &algorithm_len) == FAILURE) {
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
	int algorithm_len, argc;
	zval *args;
	zval **arg;
	const EVP_MD *digest;
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &algorithm, &algorithm_len, &args) == FAILURE) {
		return;
	}

	argc = zend_hash_num_elements(Z_ARRVAL_P(args));
	if (argc > 1) {
		zend_error(E_WARNING, "The static function %s can accept max one argument", algorithm);
		RETURN_NULL();
	}

	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(HASH_STATIC_NOT_FOUND, "Hash static function '%s' not found", algorithm);
		return;
	}

	object_init_ex(return_value, php_crypto_hash_ce);
	php_crypto_set_algorithm_name(return_value, algorithm, algorithm_len TSRMLS_CC);
	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(return_value TSRMLS_CC);
	PHP_CRYPTO_HASH_ALG(intern) = digest;

	if (argc == 1) {
		zend_hash_internal_pointer_reset(Z_ARRVAL_P(args));
		zend_hash_get_current_data(Z_ARRVAL_P(args), (void **) &arg);
		convert_to_string_ex(arg);
		if (php_crypto_hash_update(intern, Z_STRVAL_PP(arg), Z_STRLEN_PP(arg) TSRMLS_CC) == FAILURE) {
			RETURN_NULL();
		}
	}
}
/* }}} */

/* {{{ proto Crypto\Hash::__construct(string $algorithm)
   Hash constructor */
PHP_CRYPTO_METHOD(Hash, __construct)
{
	php_crypto_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	const EVP_MD *digest;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	php_crypto_set_algorithm_name(getThis(), algorithm, algorithm_len TSRMLS_CC);
	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC algorithm uses a cipher algorithm */
	if (intern->type == PHP_CRYPTO_ALG_CMAC) {
		php_crypto_set_cipher_algorithm_ex(intern, algorithm, algorithm_len TSRMLS_CC);
		return;
	}
#endif

	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(HASH_ALGORITHM_NOT_FOUND, "Hash algorithm '%s' not found", algorithm);
		return;
	}
	PHP_CRYPTO_HASH_ALG(intern) = digest;
}
/* }}} */

/* {{{ proto void Crypto\Hash::update(string $data)
   Updates hash */
PHP_CRYPTO_METHOD(Hash, update)
{
	php_crypto_algorithm_object *intern;
	char *data;
	int data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	php_crypto_hash_update(intern, data, data_len TSRMLS_CC);
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
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_MD_block_size(PHP_CRYPTO_HASH_ALG(intern)));
}

/* {{{ proto int Crypto\Hash::getSize()
   Returns hash size */
PHP_CRYPTO_METHOD(Hash, getSize)
{
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_MD_size(PHP_CRYPTO_HASH_ALG(intern)));
}
