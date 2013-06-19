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

#include <openssl/evp.h>

ZEND_BEGIN_ARG_INFO(arginfo_crypto_evp_cipher___construct, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_evp_cipher_object_methods[] = {
	PHP_CRYPTO_ME(EVP, Cipher, __construct, arginfo_crypto_evp_cipher___construct, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* cipher class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_cipher_ce;
/* cipher object handlers */
static zend_object_handlers php_crypto_evp_cipher_object_handlers;

/* algorithms getters */
typedef const EVP_MD *(*php_crypto_evp_md_algorithm_t)(void);
typedef const EVP_CIPHER *(*php_crypto_evp_cipher_algorithm_t)(void);

/* algorithm entry */
typedef struct {
	const char *name;
	union {
		php_crypto_evp_md_algorithm_t md;
		php_crypto_evp_cipher_algorithm_t cipher;
	};
} php_crypto_evp_algorithm;

#define PHP_CRYPTO_EVP_CIPHER_AE(alg) {#alg, .cipher = EVP_##alg},
#define PHP_CRYPTO_EVP_MD_AE(alg) {#alg, .md = EVP_##alg},
#define PHP_CRYPTO_EVP_LAST_AE {NULL, NULL}

static php_crypto_evp_algorithm php_crypto_evp_cipher_algorithms[] = {
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
	PHP_CRYPTO_EVP_LAST_AE
};

/* {{{ php_crypto_evp_algorigthm_find */
static php_crypto_evp_algorithm *php_crypto_evp_find_algorigthm(const char *alg, int alg_len)
{
	php_crypto_evp_algorithm *ae = php_crypto_evp_cipher_algorithms;
	while (ae->name)
	{
		if (strncmp(ae->name, alg, alg_len) == 0)
			return ae;
		ae++;
	}
	return NULL;
}

/* {{{ php_crypto_evp_cipher_object_dtor */
static void php_crypto_evp_cipher_object_dtor(void *object, zend_object_handle handle TSRMLS_DC)
{
	zend_objects_destroy_object(object, handle TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_evp_cipher_object_free */
static void php_crypto_evp_cipher_object_free(zend_object *object TSRMLS_DC)
{
	php_crypto_evp_cipher_object *intern = (php_crypto_evp_cipher_object *) object;

	EVP_CIPHER_CTX_cleanup(intern->context);
	efree(intern->context);

	if (intern->algorithm) {
		efree(intern->algorithm);
	}
	
	zend_object_std_dtor(&intern->zo TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ php_crypto_evp_cipher_object_create */
static zend_object_value php_crypto_evp_cipher_object_create_ex(zend_class_entry *class_type, php_crypto_evp_cipher_object **ptr TSRMLS_DC)
{
	zend_object_value retval;
	php_crypto_evp_cipher_object *intern;

	/* Allocate memory for it */
	intern = (php_crypto_evp_cipher_object *) emalloc(sizeof(php_crypto_evp_cipher_object));
	memset(&intern->zo, 0, sizeof(zend_object));
	if (ptr) {
		*ptr = intern;
	}
	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	object_properties_init(&intern->zo, class_type);

	intern->context = (EVP_CIPHER_CTX *) emalloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(intern->context);

	intern->algorithm = NULL;

	retval.handle = zend_objects_store_put(
		intern,
		(zend_objects_store_dtor_t) php_crypto_evp_cipher_object_dtor,
		(zend_objects_free_object_storage_t) php_crypto_evp_cipher_object_free,
		NULL TSRMLS_CC);
	retval.handlers = &php_crypto_evp_cipher_object_handlers;

	return retval;
}
/* }}} */

/* {{{ php_crypto_evp_cipher_object_create */
static zend_object_value php_crypto_evp_cipher_object_create(zend_class_entry *class_type TSRMLS_DC)
{
	return php_crypto_evp_cipher_object_create_ex(class_type, NULL TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_evp_cipher_object_clone */
zend_object_value php_crypto_evp_cipher_object_clone(zval *this_ptr TSRMLS_DC)
{
	php_crypto_evp_cipher_object *new_obj = NULL;
	php_crypto_evp_cipher_object *old_obj = (php_crypto_evp_cipher_object *) zend_object_store_get_object(this_ptr TSRMLS_CC);
	zend_object_value new_ov = php_crypto_evp_cipher_object_create_ex(old_obj->zo.ce, &new_obj TSRMLS_CC);

	zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);
	
	return new_ov;
}
/* }}} */


/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(crypto_evp)
{
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, Cipher), php_crypto_evp_cipher_object_methods);
	ce.create_object = php_crypto_evp_cipher_object_create;
	memcpy(&php_crypto_evp_cipher_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_crypto_evp_cipher_object_handlers.clone_obj = php_crypto_evp_cipher_object_clone;
	php_crypto_evp_cipher_ce = zend_register_internal_class(&ce TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ proto Crypto\EVP\Cipher::__construct(string algorithm)
   Cipher constructor */
PHP_CRYPTO_METHOD(EVP, Cipher, __construct)
{
	php_crypto_evp_cipher_object *intern;
	php_crypto_evp_algorithm *ae;
	char *algorithm;
	int algorithm_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &algorithm, &algorithm_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_evp_cipher_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	intern->algorithm = estrdup(algorithm);

	ae = php_crypto_evp_find_algorigthm(algorithm, algorithm_len);
	if (ae) {
		intern->cipher = ae->cipher();
		php_printf("FOUND\n");
	}
	else {
		php_printf("NOT FOUND\n");
	}
}
/* }}} */
