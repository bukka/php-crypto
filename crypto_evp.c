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

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_evp_cipher_init, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_evp_cipher_update, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_evp_cipher_crypt, 0, 0, 2)
ZEND_ARG_INFO(0, data)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
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
	PHP_CRYPTO_ME(EVP, Cipher, __construct,      arginfo_crypto_evp_algorithm___construct, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, encryptInit,      arginfo_crypto_evp_cipher_init, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, encryptUpdate,    arginfo_crypto_evp_cipher_update, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, encryptFinal,     NULL, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, encrypt,          arginfo_crypto_evp_cipher_crypt, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, decryptInit,      arginfo_crypto_evp_cipher_init, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, decryptUpdate,    arginfo_crypto_evp_cipher_update, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, decryptFinal,     NULL, ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(EVP, Cipher, decrypt,          arginfo_crypto_evp_cipher_crypt, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_algorithm_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_md_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_cipher_ce;

/* exception entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_evp_algorithm_exception_ce;
/* exception codes */
#define PHP_CRYPTO_EVP_ALG_E_INVALID  1
#define PHP_CRYPTO_EVP_ALG_E_IV       2
#define PHP_CRYPTO_EVP_ALG_E_KEY      3
#define PHP_CRYPTO_EVP_ALG_E_DIGEST   4
#define PHP_CRYPTO_EVP_ALG_E_ENCRYPT  5
#define PHP_CRYPTO_EVP_ALG_E_DECRYPT  6

/* object handlers */
static zend_object_handlers php_crypto_evp_algorithm_object_handlers;

#define php_crypto_evp_get_algorithm_property(this_object) \
	zend_read_property(php_crypto_evp_algorithm_ce, this_object, "algorithm", sizeof("algorithm")-1, 1 TSRMLS_CC)

#define php_crypto_evp_get_algorithm_property_string(this_object) \
	Z_STRVAL_P(php_crypto_evp_get_algorithm_property(this_object))

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

	if (new_obj->type == PHP_CRYPTO_EVP_ALG_CIPHER) {
		EVP_CIPHER_CTX_copy(new_obj->cipher.ctx, old_obj->cipher.ctx);
	} else if (new_obj->type == PHP_CRYPTO_EVP_ALG_MD) {
		EVP_MD_CTX_copy(new_obj->md.ctx, old_obj->md.ctx);
	}
	
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

	/* Algorithm Exception class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(EVP, AlgorithmException), NULL);
	php_crypto_evp_algorithm_exception_ce = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
		
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

/* {{{ proto string Crypto\EVP\Algorithm::getAlgorithm()
   Returns algorithm string */
PHP_CRYPTO_METHOD(EVP, Algorithm, getAlgorithm)
{
	zval *algorithm = php_crypto_evp_get_algorithm_property(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
}
/* }}} */

/* {{{ proto Crypto\EVP\MD::__construct(string algorithm)
   MD (Message Digest) constructor */
PHP_CRYPTO_METHOD(EVP, MD, __construct)
{
	php_crypto_evp_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	const EVP_MD *digest;
	
	intern = php_crypto_evp_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	digest = EVP_get_digestbyname(algorithm);
	if (digest) {
		intern->md.alg = digest;
	}
	else {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION_EX(DIGEST_NOT_FOUND, "Message Digest '%s' algorithm not found", algorithm);
	}
}
/* }}} */

/* {{{ proto Crypto\EVP\Cipher::__construct(string algorithm)
   Cipher constructor */
PHP_CRYPTO_METHOD(EVP, Cipher, __construct)
{
	php_crypto_evp_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	const EVP_CIPHER *cipher;

	intern = php_crypto_evp_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	cipher = EVP_get_cipherbyname(algorithm);
	if (cipher) {
		intern->cipher.alg = cipher;
	}
	else {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher '%s' algorithm not found", algorithm);
	}
}
/* }}} */

/* {{{ php_crypto_evp_cipher_check_key */
static int php_crypto_evp_cipher_check_key(zval *zobject, php_crypto_evp_algorithm_object *intern, int key_len)
{
	int alg_key_len = EVP_CIPHER_key_length(intern->cipher.alg);
	
	if (key_len != alg_key_len) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_KEY_LENGTH, "Invalid length of key for cipher '%s' algorithm (required length: %d)",
													php_crypto_evp_get_algorithm_property_string(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_evp_cipher_check_iv */
static int php_crypto_evp_cipher_check_iv(zval *zobject, php_crypto_evp_algorithm_object *intern, int iv_len)
{
	int alg_iv_len = EVP_CIPHER_iv_length(intern->cipher.alg);
	
	if (iv_len != alg_iv_len) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_IV_LENGTH, "Invalid length of initial vector (IV) for cipher '%s' algorithm (required length: %d)",
													php_crypto_evp_get_algorithm_property_string(zobject), alg_iv_len);
		
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_evp_cipher_encrypt_init */
static php_crypto_evp_algorithm_object *php_crypto_evp_cipher_encrypt_init(zval *zobject, char *key, int key_len, char *iv, int iv_len)
{
	php_crypto_evp_algorithm_object *intern = (php_crypto_evp_algorithm_object *) zend_object_store_get_object(zobject TSRMLS_CC);
	
	/* check key length */
	if (php_crypto_evp_cipher_check_key(zobject, intern, key_len) == FAILURE) {
		return NULL;
	}
	/* check initialization vector length */
	if (php_crypto_evp_cipher_check_iv(zobject, intern, iv_len) == FAILURE) {
		return NULL;
	}
	
	/* check algorithm status */
	if (intern->status == PHP_CRYPTO_EVP_ALG_STATUS_DECRYPT) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_INIT_STATUS, "Cipher object is already used for decryption");
		return NULL;
	}
	/* initialize encryption */
	if (!EVP_EncryptInit_ex(intern->cipher.ctx, intern->cipher.alg, NULL, key, iv)) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_INIT_FAILED, "Initialization of cipher encryption failed");
		return NULL;
	}
	intern->status = PHP_CRYPTO_EVP_ALG_STATUS_ENCRYPT;
	return intern;
}
/* }}} */

/* {{{ proto void Crypto\EVP\Cipher::encryptInit(string key [, string iv])
   Cipher encryption initialization */
PHP_CRYPTO_METHOD(EVP, Cipher, encryptInit)
{
	char *key, *iv = NULL;
	int key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	php_crypto_evp_cipher_encrypt_init(getThis(), key, key_len, iv, iv_len);
}

/* {{{ proto string Crypto\EVP\Cipher::encryptUpdate(string data)
   Cipher encryption update */
PHP_CRYPTO_METHOD(EVP, Cipher, encryptUpdate)
{
	php_crypto_evp_algorithm_object *intern;
	unsigned char *outbuf;
	char *data;
	int data_len, outbuf_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_evp_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	
	/* check algorithm status */
	if (intern->status != PHP_CRYPTO_EVP_ALG_STATUS_ENCRYPT) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_UPDATE_STATUS, "Cipher object has not been initialized for encryption yet");
		return;
	}

	outbuf_len = data_len + EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* update encryption context */
	if (!EVP_EncryptUpdate(intern->cipher.ctx, outbuf, &outbuf_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_UPDATE_FAILED, "Updating of cipher encryption failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
}

/* {{{ proto string Crypto\EVP\Cipher::encryptFinal()
   Cipher encryption finalization */
PHP_CRYPTO_METHOD(EVP, Cipher, encryptFinal)
{
	php_crypto_evp_algorithm_object *intern;
	unsigned char *outbuf;
	int outbuf_len;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_evp_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	
	/* check algorithm status */
	if (intern->status != PHP_CRYPTO_EVP_ALG_STATUS_ENCRYPT) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINAL_STATUS, "Cipher object has not been initialized for encryption yet");
		return;
	}
	
	outbuf_len = EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* finalize encryption context */
	if (!EVP_EncryptFinal_ex(intern->cipher.ctx, outbuf, &outbuf_len)) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINAL_FAILED, "Finalizing of cipher encryption failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	intern->status = PHP_CRYPTO_EVP_ALG_STATUS_CLEAR;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
}

/* {{{ proto Crypto\EVP\Cipher::encrypt(string data, string key [, string iv])
   Cipher encryption */
PHP_CRYPTO_METHOD(EVP, Cipher, encrypt)
{
	php_crypto_evp_algorithm_object *intern;
	unsigned char *outbuf;
	char *data, *key, *iv = NULL;
	int outbuf_len, outbuf_update_len, outbuf_final_len, data_len, key_len, iv_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s", &data, &data_len, &key, &key_len, &iv, &iv_len) == FAILURE) {
		return;
	}

	intern = php_crypto_evp_cipher_encrypt_init(getThis(), key, key_len, iv, iv_len);
	if (intern == NULL) {
		return;
	}

	outbuf_len = data_len + EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));

	/* update encryption context */
	if (!EVP_EncryptUpdate(intern->cipher.ctx, outbuf, &outbuf_update_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_UPDATE_FAILED, "Updating of cipher encryption failed");
		efree(outbuf);
		return;
	}
	/* finalize encryption context */
	if (!EVP_EncryptFinal_ex(intern->cipher.ctx, outbuf + outbuf_update_len, &outbuf_final_len)) {
		PHP_CRYPTO_EVP_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINAL_FAILED, "Finalizing of cipher encryption failed");
		efree(outbuf);
		return;
	}
	outbuf_len = outbuf_update_len + outbuf_final_len;
	outbuf[outbuf_len] = 0;
	intern->status = PHP_CRYPTO_EVP_ALG_STATUS_CLEAR;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
}

/* {{{ proto Crypto\EVP\Cipher::decryptInit(string key [, string iv])
   Cipher decryption initialization */
PHP_CRYPTO_METHOD(EVP, Cipher, decryptInit)
{
	zval *object = getThis();
	
}

/* {{{ proto Crypto\EVP\Cipher::decryptUpdate(string data)
   Cipher decryption update */
PHP_CRYPTO_METHOD(EVP, Cipher, decryptUpdate)
{
	zval *object = getThis();
	
}

/* {{{ proto Crypto\EVP\Cipher::decryptFinal()
   Cipher decryption finalization */
PHP_CRYPTO_METHOD(EVP, Cipher, decryptFinal)
{
	zval *object = getThis();
	
}

/* {{{ proto Crypto\EVP\Cipher::decrypt(string data, string key [, string iv])
   Cipher decryption */
PHP_CRYPTO_METHOD(EVP, Cipher, decrypt)
{
	zval *object = getThis();
	
}
