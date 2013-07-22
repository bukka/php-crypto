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
#include "php_crypto_evp.h"
#include "zend_exceptions.h"

#include <openssl/evp.h>

ZEND_BEGIN_ARG_INFO(arginfo_crypto_evp_algorithm___construct, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_evp_algorithm_object_methods[] = {
	PHP_CRYPTO_ABSTRACT_ME(EVP, Algorithm, __construct, arginfo_crypto_evp_algorithm___construct)
	PHP_CRYPTO_ME(EVP, Algorithm, getAlgorithm, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry php_crypto_evp_md_object_methods[] = {
	PHP_CRYPTO_ME(EVP, MD, __construct, arginfo_crypto_evp_algorithm___construct, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry php_crypto_evp_cipher_object_methods[] = {
	PHP_CRYPTO_ME(EVP, Cipher, __construct, arginfo_crypto_evp_algorithm___construct, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
    PHP_FE_END
};


/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_cipher_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_md_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_algorithm_ce;
/* exception entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_invalid_algorithm_exc_ce;

/* object handlers */
static zend_object_handlers php_crypto_evp_algorithm_object_handlers;

/* algorithms getters */
typedef const EVP_MD *(*php_crypto_evp_md_algorithm_t)(void);
typedef const EVP_CIPHER *(*php_crypto_evp_cipher_algorithm_t)(void);

/* algorithm entry */
typedef struct {
	const char *name;
	php_crypto_evp_algorithm_type type;
	union {
		php_crypto_evp_md_algorithm_t md;
		php_crypto_evp_cipher_algorithm_t cipher;
	};
} php_crypto_evp_algorithm;

#define PHP_CRYPTO_EVP_CIPHER_AE(alg) {#alg, PHP_CRYPTO_EVP_ALG_CIPHER, .cipher = EVP_##alg},
#define PHP_CRYPTO_EVP_MD_AE(alg) {#alg, PHP_CRYPTO_EVP_ALG_MD, .md = EVP_##alg},
#define PHP_CRYPTO_EVP_LAST_AE {NULL, PHP_CRYPTO_EVP_ALG_NONE, NULL}

static php_crypto_evp_algorithm php_crypto_evp_algorithms[] = {
	/* MD */
#ifndef OPENSSL_NO_MD2
	PHP_CRYPTO_EVP_MD_AE(md2)
#endif
#ifndef OPENSSL_NO_MD4
	PHP_CRYPTO_EVP_MD_AE(md4)
#endif
#ifndef OPENSSL_NO_MD5
	PHP_CRYPTO_EVP_MD_AE(md5)
#endif
#ifndef OPENSSL_NO_SHA
	PHP_CRYPTO_EVP_MD_AE(sha)
	PHP_CRYPTO_EVP_MD_AE(sha1)
	PHP_CRYPTO_EVP_MD_AE(dss)
	PHP_CRYPTO_EVP_MD_AE(dss1)
	/* PHP_CRYPTO_EVP_MD_AE(ecdsa) - missing in my lib ? */
#endif
#ifndef OPENSSL_NO_SHA256
	PHP_CRYPTO_EVP_MD_AE(sha224)
	PHP_CRYPTO_EVP_MD_AE(sha256)
#endif
#ifndef OPENSSL_NO_SHA512
	PHP_CRYPTO_EVP_MD_AE(sha384)
	PHP_CRYPTO_EVP_MD_AE(sha512)
#endif
#ifndef OPENSSL_NO_MDC2
	PHP_CRYPTO_EVP_MD_AE(mdc2)
#endif
#ifndef OPENSSL_NO_RIPEMD
	PHP_CRYPTO_EVP_MD_AE(ripemd160)
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	PHP_CRYPTO_EVP_MD_AE(whirlpool)
#endif
	/* Cipher */
#ifndef OPENSSL_NO_DES
	PHP_CRYPTO_EVP_CIPHER_AE(des_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_cfb64)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede_cfb64)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede_cfb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_cfb64)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_cfb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_cfb1)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_cfb8)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(des_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(des_ede3_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(desx_cbc)
#endif
#ifndef OPENSSL_NO_AES
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cfb1)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cfb8)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cfb128)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cfb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_ctr)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_ccm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_gcm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_xts)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_128_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cfb1)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cfb8)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cfb128)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cfb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_ctr)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_ccm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_gcm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_192_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_ecb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cbc)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cfb1)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cfb8)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cfb128)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cfb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_ofb)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_ctr)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_ccm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_gcm)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_xts)
	PHP_CRYPTO_EVP_CIPHER_AE(aes_256_cbc)
#endif
	
	PHP_CRYPTO_EVP_LAST_AE
};

#define php_crypto_evp_find_algorigthm(alg, type) php_crypto_evp_find_algorigthm_ex(alg, strlen(alg), type)

/* {{{ php_crypto_evp_find_algorithm */
static php_crypto_evp_algorithm *php_crypto_evp_find_algorigthm_ex(const char *alg, int alg_len, php_crypto_evp_algorithm_type type)
{
	php_crypto_evp_algorithm *ae = php_crypto_evp_algorithms;
	
	while (ae->name)
	{
		if (strncmp(ae->name, alg, alg_len) == 0)
			return ae->type == type ? ae : NULL;
		ae++;
	}
	
	return NULL;
}
/* }}} */


/* {{{ php_crypto_evp_algorithm_object_dtor */
static void php_crypto_evp_algorithm_object_dtor(void *object, zend_object_handle handle TSRMLS_DC)
{
	zend_objects_destroy_object(object, handle TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_evp_algorithm_object_free */
static void php_crypto_evp_algorithm_object_free(zend_object *object TSRMLS_DC)
{
	php_crypto_evp_algorithm_object *intern = (php_crypto_evp_algorithm_object *) object;

	if (intern->type == PHP_CRYPTO_EVP_ALG_CIPHER) {
		EVP_CIPHER_CTX_cleanup(intern->cipher.ctx);
		efree(intern->cipher.ctx);
	} else if (intern->type == PHP_CRYPTO_EVP_ALG_MD) {
		EVP_MD_CTX_cleanup(intern->md.ctx);
		efree(intern->md.ctx);
	}
	
	zend_object_std_dtor(&intern->zo TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ php_crypto_evp_algorithm_object_create */
static zend_object_value php_crypto_evp_algorithm_object_create_ex(zend_class_entry *class_type, php_crypto_evp_algorithm_object **ptr TSRMLS_DC)
{
	zend_object_value retval;
	php_crypto_evp_algorithm_object *intern;

	/* Allocate memory for it */
	intern = (php_crypto_evp_algorithm_object *) emalloc(sizeof(php_crypto_evp_algorithm_object));
	memset(intern, 0, sizeof(php_crypto_evp_algorithm_object));
	if (ptr) {
		*ptr = intern;
	}
	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	object_properties_init(&intern->zo, class_type);

	if (class_type == php_crypto_evp_cipher_ce) {
		intern->type = PHP_CRYPTO_EVP_ALG_CIPHER;
		intern->cipher.ctx = (EVP_CIPHER_CTX *) emalloc(sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(intern->cipher.ctx);
	} else if (class_type == php_crypto_evp_md_ce) {
		intern->type = PHP_CRYPTO_EVP_ALG_MD;
		intern->md.ctx = (EVP_MD_CTX *) emalloc(sizeof(EVP_MD_CTX));
		EVP_MD_CTX_init(intern->md.ctx);
	} else {
		intern->type = PHP_CRYPTO_EVP_ALG_NONE;
	}
	
	retval.handlers = &php_crypto_evp_algorithm_object_handlers;
	retval.handle = zend_objects_store_put(
		intern,
		(zend_objects_store_dtor_t) php_crypto_evp_algorithm_object_dtor,
		(zend_objects_free_object_storage_t) php_crypto_evp_algorithm_object_free,
		NULL TSRMLS_CC);
	
	return retval;
}
/* }}} */

/* {{{ php_crypto_evp_algorithm_object_create */
static zend_object_value php_crypto_evp_algorithm_object_create(zend_class_entry *class_type TSRMLS_DC)
{
	return php_crypto_evp_algorithm_object_create_ex(class_type, NULL TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_evp_algorith_object_clone */
zend_object_value php_crypto_evp_algorithm_object_clone(zval *this_ptr TSRMLS_DC)
{
	php_crypto_evp_algorithm_object *new_obj = NULL;
	php_crypto_evp_algorithm_object *old_obj = (php_crypto_evp_algorithm_object *) zend_object_store_get_object(this_ptr TSRMLS_CC);
	zend_object_value new_ov = php_crypto_evp_algorithm_object_create_ex(old_obj->zo.ce, &new_obj TSRMLS_CC);

	zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);
	
	return new_ov;
}
/* }}} */


/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_evp)
{
	zend_class_entry ce;

	/* Algorithm class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, Algorithm), php_crypto_evp_algorithm_object_methods);
	ce.create_object = php_crypto_evp_algorithm_object_create;
	memcpy(&php_crypto_evp_algorithm_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_crypto_evp_algorithm_object_handlers.clone_obj = php_crypto_evp_algorithm_object_clone;
	php_crypto_evp_algorithm_ce = zend_register_internal_class(&ce TSRMLS_CC);
	zend_declare_property_null(php_crypto_evp_algorithm_ce, "algorithm", sizeof("algorithm")-1, ZEND_ACC_PROTECTED TSRMLS_CC);

	/* InvalidAlgorithmException class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, InvalidAlgorithmException), NULL);
	php_crypto_evp_invalid_algorithm_exc_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	
	/* MD class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, MD), php_crypto_evp_md_object_methods);
	php_crypto_evp_md_ce = zend_register_internal_class_ex(&ce, php_crypto_evp_algorithm_ce, NULL TSRMLS_CC);

	/* Cipher class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, Cipher), php_crypto_evp_cipher_object_methods);
	php_crypto_evp_cipher_ce = zend_register_internal_class_ex(&ce, php_crypto_evp_algorithm_ce, NULL TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_evp_get_algorithm
   It is sort of Cryptho\EVP\Algorithm::_construct */
static php_crypto_evp_algorithm_object *php_crypto_evp_get_algorithm_object(char **algorithm, int *algorithm_len, INTERNAL_FUNCTION_PARAMETERS)
{
	php_crypto_evp_algorithm_object *intern;
		
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", algorithm, algorithm_len) == FAILURE) {
		return NULL;
	}
	zend_update_property_stringl(php_crypto_evp_algorithm_ce, getThis(), "algorithm", sizeof("algorithm")-1, *algorithm, *algorithm_len TSRMLS_CC);

	intern = (php_crypto_evp_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	return intern;
}
/* }}} */

PHP_CRYPTO_METHOD(EVP, Algorithm, getAlgorithm)
{
	zval *algorithm = zend_read_property(php_crypto_evp_algorithm_ce, getThis(), "algorithm", sizeof("algorithm")-1, 1 TSRMLS_CC);
	RETURN_ZVAL(algorithm, 1, 0);
}


/* {{{ proto Crypto\EVP\MD::__construct(string algorithm)
   MD (Message Digest) constructor */
PHP_CRYPTO_METHOD(EVP, MD, __construct)
{
	php_crypto_evp_algorithm_object *intern;
	php_crypto_evp_algorithm *ae;
	char *algorithm;
	int algorithm_len;
	
	intern = php_crypto_evp_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	ae = php_crypto_evp_find_algorigthm_ex(algorithm, algorithm_len, PHP_CRYPTO_EVP_ALG_MD);
	if (ae) {
		intern->md.ao = ae->md();
	}
	else {
		zend_throw_exception(php_crypto_evp_invalid_algorithm_exc_ce, "MD algorithm not found", 0 TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto Crypto\EVP\Cipher::__construct(string algorithm)
   Cipher constructor */
PHP_CRYPTO_METHOD(EVP, Cipher, __construct)
{
	php_crypto_evp_algorithm_object *intern;
	php_crypto_evp_algorithm *ae;
	char *algorithm;
	int algorithm_len;

	intern = php_crypto_evp_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	ae = php_crypto_evp_find_algorigthm_ex(algorithm, algorithm_len, PHP_CRYPTO_EVP_ALG_CIPHER);
	if (ae) {
		intern->cipher.ao = ae->cipher();
	}
	else {
		zend_throw_exception(php_crypto_evp_invalid_algorithm_exc_ce, "Cipher algorithm not found", 0 TSRMLS_CC);
	}
}
/* }}} */
