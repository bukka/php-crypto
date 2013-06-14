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

PHP_CRYPTO_API zend_class_entry *php_crypto_evp_cipher_ce;

static zend_object_handlers php_crypto_evp_cipher_object_handlers;


static const zend_function_entry php_crypto_evp_cipher_object_methods[] = {
    PHP_FE_END
};

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
