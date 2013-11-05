/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Jakub Zelenka <jakub.php@gmail.com>                          |
  +----------------------------------------------------------------------+
*/

#include "php.h"
#include "php_crypto.h"
#include "php_crypto_alg.h"
#include "zend_exceptions.h"

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
ZEND_ARG_INFO(0, extra_info)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_init, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_mode, 0)
ZEND_ARG_INFO(0, mode)
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
	PHP_CRYPTO_CIPHER_MODE_ENTRY(ECB, EVP_CIPH_ECB_MODE)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CBC, EVP_CIPH_CBC_MODE)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CFB, EVP_CIPH_CFB_MODE)
	PHP_CRYPTO_CIPHER_MODE_ENTRY(OFB, EVP_CIPH_OFB_MODE)
#ifdef EVP_CIPH_CTR_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CTR, EVP_CIPH_CTR_MODE)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(CTR)
#endif
#ifdef EVP_CIPH_GCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(GCM, EVP_CIPH_GCM_MODE)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(GCM)
#endif
#ifdef EVP_CIPH_CCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(CCM, EVP_CIPH_CCM_MODE)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(CCM)
#endif
#ifdef EVP_CIPH_XTS_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY(XTS, EVP_CIPH_XTS_MODE)
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
	php_crypto_object_properties_init(&intern->zo, class_type);

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
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_KEY_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_IV_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_INIT_FAILED);
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

/* METHODS */

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
static php_crypto_algorithm_object *php_crypto_get_algorithm_object_ex(const char *algorithm, int algorithm_len, zval *object TSRMLS_DC)
{
	zend_update_property_stringl(php_crypto_algorithm_ce, object, "algorithm", sizeof("algorithm")-1, algorithm, algorithm_len TSRMLS_CC);
	return (php_crypto_algorithm_object *) zend_object_store_get_object(object TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_get_algorithm_object */
static php_crypto_algorithm_object *php_crypto_get_algorithm_object(char **algorithm, int *algorithm_len, INTERNAL_FUNCTION_PARAMETERS)
{
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", algorithm, algorithm_len) == FAILURE) {
		return NULL;
	}
	return php_crypto_get_algorithm_object_ex(*algorithm, *algorithm_len, getThis() TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_get_cipher_mode_by_name */
static const php_crypto_cipher_mode *php_crypto_get_cipher_mode_by_name(const char *mode_name, int mode_name_len)
{
	const php_crypto_cipher_mode *mode;

	if (mode_name_len != PHP_CRYPTO_CIPHER_MODE_LEN) {
		return NULL;
	}
	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		if (!zend_binary_strcasecmp(mode_name, PHP_CRYPTO_CIPHER_MODE_LEN, mode->name, PHP_CRYPTO_CIPHER_MODE_LEN)) {
			return mode;
		}
	}
	return NULL;
}
/* }}} */

/* {{{ php_crypto_get_cipher_mode_by_value */
static const php_crypto_cipher_mode *php_crypto_get_cipher_mode_by_value(long mode_value)
{
	const php_crypto_cipher_mode *mode;

	if (mode_value == PHP_CRYPTO_CIPHER_MODE_NOT_DEFINED) {
		return NULL;
	}
	for (mode = php_crypto_cipher_modes; mode->name[0]; mode++) {
		if (mode_value == mode->value) {
			return mode;
		}
	}
	return NULL;
}
/* }}} */

/* {{{ php_crypto_throw_cipher_not_found_exception */
static inline void php_crypto_throw_cipher_not_found_exception(const char *algorithm TSRMLS_DC)
{
	PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher '%s' algorithm not found", algorithm);
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm */
static int php_crypto_set_cipher_algorithm(php_crypto_algorithm_object *intern, const char *algorithm TSRMLS_DC)
{
	const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
	if (!cipher) {
		php_crypto_throw_cipher_not_found_exception(algorithm TSRMLS_CC);
		return FAILURE;
	}
	PHP_CRYPTO_CIPHER_ALG(intern) = cipher;
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_set_cipher_algorithm */
static int php_crypto_set_cipher_algorithm_ex(php_crypto_algorithm_object *intern,
		const char *algorithm, int algorithm_len, zval *pz_mode, zval *pz_extra_info TSRMLS_DC)
{
	const php_crypto_cipher_mode *mode;
	char alg_buf[PHP_CRYPTO_CIPHER_ALG_MAX_LEN+1], *alg_ptr;
	zval **ppz_extra_info;
	int alg_len;

	if (!pz_mode) {
		return php_crypto_set_cipher_algorithm(intern, algorithm TSRMLS_CC);
	}

	if (algorithm_len >= (PHP_CRYPTO_CIPHER_ALG_MAX_LEN - PHP_CRYPTO_CIPHER_MODE_LEN - 2)) {
		php_crypto_throw_cipher_not_found_exception(algorithm TSRMLS_CC);
		return FAILURE;
	}
	memcpy(alg_buf, algorithm, algorithm_len * sizeof (char));
	alg_buf[algorithm_len] = '-';
	alg_ptr = &alg_buf[algorithm_len + 1];

	if (Z_TYPE_P(pz_mode) == IS_LONG) {
		mode = php_crypto_get_cipher_mode_by_value(Z_LVAL_P(pz_mode));
		if (!mode) {
			PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_MODE_NOT_FOUND, "Cipher mode with integer value %d does not exist", Z_LVAL_P(pz_mode));
			return FAILURE;
		}
	} else {
		zval **ppz_mode = &pz_mode;
		conver_to_string_ex(ppz_mode);
		mode = php_crypto_get_cipher_mode_by_name(Z_STRVAL_PP(ppz_mode), Z_STRLEN_PP(ppz_mode));
		if (!mode) {
			PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_MODE_NOT_FOUND, "Cipher mode '%s' does not exist", Z_STRVAL_PP(ppz_mode));
			return FAILURE;
		}
	}
	memcpy(alg_ptr, mode->name, PHP_CRYPTO_CIPHER_MODE_LEN * sizeof (char));
	alg_ptr += PHP_CRYPTO_CIPHER_MODE_LEN;

	if (!pz_extra_info) {
		*alg_ptr = '\0';
		return php_crypto_set_cipher_algorithm(intern, alg_buf TSRMLS_CC);
	}

	ppz_extra_info = &pz_extra_info;
	convert_to_string_ex(ppz_extra_info);
	alg_len = algorithm_len + PHP_CRYPTO_CIPHER_MODE_LEN + Z_STRLEN_PP(ppz_extra_info);
	if (alg_len > PHP_CRYPTO_CIPHER_ALG_MAX_LEN) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher algorithm with name length %d does not exists", alg_len);
		return FAILURE;
	}
	*alg_ptr = '-';
	memcpy(alg_ptr, Z_STRVAL_PP(ppz_extra_info), Z_STRLEN_PP(ppz_extra_info) * sizeof (char));
	alg_buf[alg_len] = '\0';
	return php_crypto_set_cipher_algorithm(intern, alg_buf TSRMLS_CC);
}
/* }}} */

/* {{{ proto Crypto\Algorithm::__construct(string $algorithm)
   Algorithm constructor */
PHP_CRYPTO_METHOD(Algorithm, __construct)
{
	char *algorithm;
	int algorithm_len;
	php_crypto_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* {{{ proto string Crypto\Algorithm::getAlgorithmName()
   Returns algorithm string */
PHP_CRYPTO_METHOD(Algorithm, getAlgorithmName)
{
	zval *algorithm = PHP_CRYPTO_GET_ALGORITHM_NAME_EX(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
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
	
	if (EVP_get_cipherbyname(algorithm)) {
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
	zval *args;
	zval **arg;
	const EVP_MD *digest;
	php_crypto_algorithm_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &algorithm, &algorithm_len, &args) == FAILURE) {
		return;
	}

	argc = zend_hash_num_elements(Z_ARRVAL_P(args));
	if (argc > 2) {
		zend_error(E_WARNING, "The static function %s can accept max two arguments", algorithm);
		RETURN_NULL();
	}

	/*
	digest = EVP_get_digestbyname(algorithm);
	if (!digest) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(HASH_STATIC_NOT_FOUND, "Hash static function '%s' not found", algorithm);
		return;
	}

	object_init_ex(return_value, php_crypto_hash_ce);
	intern = php_crypto_get_algorithm_object_ex(algorithm, algorithm_len, return_value TSRMLS_CC);
	PHP_CRYPTO_HASH_ALG(intern) = digest;

	if (argc == 1) {
		zend_hash_internal_pointer_reset(Z_ARRVAL_P(args));
		zend_hash_get_current_data(Z_ARRVAL_P(args), (void **) &arg);
		convert_to_string_ex(arg);
		if (php_crypto_hash_update(intern, Z_STRVAL_PP(arg), Z_STRLEN_PP(arg) TSRMLS_CC) == FAILURE) {
			RETURN_NULL();
		}
	}
	*/
}
/* }}} */

/* {{{ proto Crypto\Cipher::__construct(string $algorithm, int $mode = NULL, string $extra_info = NULL)
   Cipher constructor */
PHP_CRYPTO_METHOD(Cipher, __construct)
{
	php_crypto_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	zval *mode = NULL, *extra_info = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zz", algorithm, algorithm_len, &mode, &extra_info) == FAILURE) {
		return;
	}
	intern = php_crypto_get_algorithm_object_ex(algorithm, algorithm_len, getThis() TSRMLS_CC);
	if (!intern) {
		return;
	}
	php_crypto_set_cipher_algorithm_ex(intern, algorithm, algorithm_len, mode, extra_info TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_cipher_check_key */
static int php_crypto_cipher_check_key(zval *zobject, php_crypto_algorithm_object *intern, int key_len TSRMLS_DC)
{
	int alg_key_len = EVP_CIPHER_key_length(PHP_CRYPTO_CIPHER_ALG(intern));
	
	if (key_len != alg_key_len) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_KEY_LENGTH,
			"Invalid length of key for cipher '%s' algorithm (required length: %d)",
			PHP_CRYPTO_GET_ALGORITHM_NAME(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_iv */
static int php_crypto_cipher_check_iv(zval *zobject, php_crypto_algorithm_object *intern, int iv_len TSRMLS_DC)
{
	int alg_iv_len = EVP_CIPHER_iv_length(PHP_CRYPTO_CIPHER_ALG(intern));
	
	if (iv_len != alg_iv_len) {
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
	
	/* check key length */
	
	if (php_crypto_cipher_check_key(zobject, intern, key_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}
	/* check initialization vector length */
	if (php_crypto_cipher_check_iv(zobject, intern, iv_len TSRMLS_CC) == FAILURE) {
		return NULL;
	}
	
	/* check algorithm status */
	if (enc && intern->status == PHP_CRYPTO_ALG_STATUS_DECRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_INIT_STATUS, "Cipher object is already used for decryption");
		return NULL;
	} else if (!enc && intern->status == PHP_CRYPTO_ALG_STATUS_ENCRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_INIT_STATUS, "Cipher object is already used for encryption");
		return NULL;
	}
	/* initialize encryption */
	if (!EVP_CipherInit_ex(PHP_CRYPTO_CIPHER_CTX(intern), PHP_CRYPTO_CIPHER_ALG(intern), NULL, (const unsigned char *) key, (const unsigned char *) iv, enc)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_INIT_FAILED, "Initialization of cipher failed");
		return NULL;
	}
	intern->status = (enc ? PHP_CRYPTO_ALG_STATUS_ENCRYPT : PHP_CRYPTO_ALG_STATUS_DECRYPT);
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

/* {{{ php_crypto_cipher_update */
static inline void php_crypto_cipher_update(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	php_crypto_algorithm_object *intern;
	unsigned char *outbuf;
	char *data;
	int data_len, outbuf_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	/* check algorithm status */
	if (enc && intern->status != PHP_CRYPTO_ALG_STATUS_ENCRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_UPDATE_STATUS, "Cipher object is not initialized for encryption");
		return;
	} else if (!enc && intern->status != PHP_CRYPTO_ALG_STATUS_DECRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_UPDATE_STATUS, "Cipher object is not initialized for decryption");
		return;
	}

	outbuf_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* update encryption context */
	if (!EVP_CipherUpdate(PHP_CRYPTO_CIPHER_CTX(intern), outbuf, &outbuf_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_UPDATE_FAILED, "Updating of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
}

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
	if (enc && intern->status != PHP_CRYPTO_ALG_STATUS_ENCRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINISH_STATUS, "Cipher object is not initialized for encryption");
		return;
	} else if (!enc && intern->status != PHP_CRYPTO_ALG_STATUS_DECRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_FINISH_STATUS, "Cipher object is not initialized for decryption");
		return;
	}
	
	outbuf_len = EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(PHP_CRYPTO_CIPHER_CTX(intern), outbuf, &outbuf_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_FINISH_FAILED, "Finalizing of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
}
/* }}} */

/* {{{ php_crypto_cipher_crypt */
static inline void php_crypto_cipher_crypt(INTERNAL_FUNCTION_PARAMETERS, int enc)
{
	php_crypto_algorithm_object *intern;
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

	outbuf_len = data_len + EVP_CIPHER_block_size(PHP_CRYPTO_CIPHER_ALG(intern));
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));

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
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;
	RETURN_STRINGL((char *) outbuf, outbuf_len, 0);
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
	RETURN_LONG(EVP_CIPHER_mode(PHP_CRYPTO_CIPHER_ALG(intern)));
}

/* {{{ php_crypto_set_hash_algorithm */
static int php_crypto_set_hash_algorithm(php_crypto_algorithm_object *intern, char *algorithm TSRMLS_DC)
{
	const EVP_MD *digest = EVP_get_digestbyname(algorithm);
	if (digest) {
		PHP_CRYPTO_HASH_ALG(intern) = digest;
		return SUCCESS;
	} else {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(HASH_ALGORITHM_NOT_FOUND, "Hash algorithm '%s' not found", algorithm);
		return FAILURE;
	}
}
/* }}} */

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
		char *retval = (char *) emalloc(retval_len * sizeof (char));
		php_crypto_hash_bin2hex(retval, hash_value, hash_len);
		retval[retval_len-1] = 0;
		return retval;
	}
	return estrdup((char *) hash_value);
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
	intern = php_crypto_get_algorithm_object_ex(algorithm, algorithm_len, return_value TSRMLS_CC);
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
	
	intern = php_crypto_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}

#ifdef PHP_CRYPTO_HAS_CMAC
	/* CMAC algorithm uses a cipher algorithm */
	if (intern->type == PHP_CRYPTO_ALG_CMAC) {
		php_crypto_set_cipher_algorithm(intern, algorithm TSRMLS_CC);
		return;
	}
#endif

	php_crypto_set_hash_algorithm(intern, algorithm TSRMLS_CC);
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
