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

ZEND_BEGIN_ARG_INFO(arginfo_crypto_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_init, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_algorithm_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_crypt, 0, 0, 2)
ZEND_ARG_INFO(0, data)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()

static const zend_function_entry php_crypto_algorithm_object_methods[] = {
	PHP_CRYPTO_ABSTRACT_ME(Algorithm, __construct, arginfo_crypto_algorithm)
	PHP_CRYPTO_ME(Algorithm, getAlgorithm, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry php_crypto_cipher_object_methods[] = {
	PHP_CRYPTO_ME(Cipher, hasAlgorithm,     arginfo_crypto_algorithm,          ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, __construct,      arginfo_crypto_algorithm,          ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptInit,      arginfo_crypto_cipher_init,        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptUpdate,    arginfo_crypto_algorithm_data,     ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encryptFinal,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, encrypt,          arginfo_crypto_cipher_crypt,       ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptInit,      arginfo_crypto_cipher_init,        ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptUpdate,    arginfo_crypto_algorithm_data,     ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decryptFinal,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, decrypt,          arginfo_crypto_cipher_crypt,       ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getBlockSize,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getKeyLength,     NULL,                              ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Cipher, getIVLength,      NULL,                              ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry php_crypto_digest_object_methods[] = {
	PHP_CRYPTO_ME(Digest, hasAlgorithm,     arginfo_crypto_algorithm,           ZEND_ACC_STATIC|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, __construct,      arginfo_crypto_algorithm,           ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, init,             NULL,                               ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, update,           arginfo_crypto_algorithm_data,      ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, final,            NULL,                               ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, make,             arginfo_crypto_algorithm_data,      ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, getSize,          NULL,                               ZEND_ACC_PUBLIC)
	PHP_CRYPTO_ME(Digest, getBlockSize,     NULL,                               ZEND_ACC_PUBLIC)
	PHP_FE_END
};

/* class entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;
PHP_CRYPTO_API zend_class_entry *php_crypto_digest_ce;

/* exception entries */
PHP_CRYPTO_API zend_class_entry *php_crypto_algorithm_exception_ce;

/* object handlers */
static zend_object_handlers php_crypto_algorithm_object_handlers;

#define php_crypto_get_algorithm_property(this_object) \
	zend_read_property(php_crypto_algorithm_ce, this_object, "algorithm", sizeof("algorithm")-1, 1 TSRMLS_CC)

#define php_crypto_get_algorithm_property_string(this_object) \
	Z_STRVAL_P(php_crypto_get_algorithm_property(this_object))

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
		EVP_CIPHER_CTX_cleanup(intern->cipher.ctx);
		efree(intern->cipher.ctx);
	} else if (intern->type == PHP_CRYPTO_ALG_DIGEST) {
		EVP_MD_CTX_cleanup(intern->digest.ctx);
		efree(intern->digest.ctx);
	}
	
	zend_object_std_dtor(&intern->zo TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ php_crypto_algorithm_object_create */
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
		intern->cipher.ctx = (EVP_CIPHER_CTX *) emalloc(sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(intern->cipher.ctx);
	} else if (class_type == php_crypto_digest_ce) {
		intern->type = PHP_CRYPTO_ALG_DIGEST;
		intern->digest.ctx = (EVP_MD_CTX *) emalloc(sizeof(EVP_MD_CTX));
		EVP_MD_CTX_init(intern->digest.ctx);
	} else {
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
	php_crypto_algorithm_object *new_obj = NULL;
	php_crypto_algorithm_object *old_obj = (php_crypto_algorithm_object *) zend_object_store_get_object(this_ptr TSRMLS_CC);
	zend_object_value new_ov = php_crypto_algorithm_object_create_ex(old_obj->zo.ce, &new_obj TSRMLS_CC);

	zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);

	if (new_obj->type == PHP_CRYPTO_ALG_CIPHER) {
		EVP_CIPHER_CTX_copy(new_obj->cipher.ctx, old_obj->cipher.ctx);
	} else if (new_obj->type == PHP_CRYPTO_ALG_DIGEST) {
		EVP_MD_CTX_copy(new_obj->digest.ctx, old_obj->digest.ctx);
	}
	
	return new_ov;
}
/* }}} */

#define PHP_CRYPTO_DECLARE_ALG_E_CONST(aconst)	\
	zend_declare_class_constant_long(php_crypto_algorithm_exception_ce, #aconst, sizeof(#aconst)-1, PHP_CRYPTO_ALG_E(aconst) TSRMLS_CC)

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(crypto_evp)
{
	zend_class_entry ce;
	int alg_error_code = 1;

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
	/* Declare AlorithmExcption class constants for error codes */
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_NOT_FOUND);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_KEY_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_IV_LENGTH);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_INIT_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_UPDATE_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(CIPHER_FINAL_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_INIT_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(ENCRYPT_FINAL_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_INIT_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DECRYPT_FINAL_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_INIT_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_UPDATE_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_FINAL_FAILED);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_UPDATE_STATUS);
	PHP_CRYPTO_DECLARE_ALG_E_CONST(DIGEST_FINAL_STATUS);
	
	/* Digest class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Digest), php_crypto_digest_object_methods);
	php_crypto_digest_ce = zend_register_internal_class_ex(&ce, php_crypto_algorithm_ce, NULL TSRMLS_CC);

	/* Cipher class */
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(Cipher), php_crypto_cipher_object_methods);
	php_crypto_cipher_ce = zend_register_internal_class_ex(&ce, php_crypto_algorithm_ce, NULL TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_get_algorithm
   It is sort of Crypto\Algorithm::_construct */
static php_crypto_algorithm_object *php_crypto_get_algorithm_object(char **algorithm, int *algorithm_len, INTERNAL_FUNCTION_PARAMETERS)
{
	php_crypto_algorithm_object *intern;
		
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", algorithm, algorithm_len) == FAILURE) {
		return NULL;
	}
	zend_update_property_stringl(php_crypto_algorithm_ce, getThis(), "algorithm", sizeof("algorithm")-1, *algorithm, *algorithm_len TSRMLS_CC);

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);

	return intern;
}
/* }}} */

/* {{{ proto string Crypto\Algorithm::getAlgorithm()
   Returns algorithm string */
PHP_CRYPTO_METHOD(Algorithm, getAlgorithm)
{
	zval *algorithm = php_crypto_get_algorithm_property(getThis());
	RETURN_ZVAL(algorithm, 1, 0);
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

/* {{{ proto Crypto\Cipher::__construct(string $algorithm)
   Cipher constructor */
PHP_CRYPTO_METHOD(Cipher, __construct)
{
	php_crypto_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	const EVP_CIPHER *cipher;

	intern = php_crypto_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	cipher = EVP_get_cipherbyname(algorithm);
	if (cipher) {
		intern->cipher.alg = cipher;
	} else {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_NOT_FOUND, "Cipher '%s' algorithm not found", algorithm);
	}
}
/* }}} */

/* {{{ php_crypto_cipher_check_key */
static int php_crypto_cipher_check_key(zval *zobject, php_crypto_algorithm_object *intern, int key_len TSRMLS_DC)
{
	int alg_key_len = EVP_CIPHER_key_length(intern->cipher.alg);
	
	if (key_len != alg_key_len) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_KEY_LENGTH, "Invalid length of key for cipher '%s' algorithm (required length: %d)",
													php_crypto_get_algorithm_property_string(zobject), alg_key_len);
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_cipher_check_iv */
static int php_crypto_cipher_check_iv(zval *zobject, php_crypto_algorithm_object *intern, int iv_len TSRMLS_DC)
{
	int alg_iv_len = EVP_CIPHER_iv_length(intern->cipher.alg);
	
	if (iv_len != alg_iv_len) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(CIPHER_IV_LENGTH, "Invalid length of initial vector (IV) for cipher '%s' algorithm (required length: %d)",
													php_crypto_get_algorithm_property_string(zobject), alg_iv_len);
		
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
	if (!EVP_CipherInit_ex(intern->cipher.ctx, intern->cipher.alg, NULL, key, iv, enc)) {
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

	outbuf_len = data_len + EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* update encryption context */
	if (!EVP_CipherUpdate(intern->cipher.ctx, outbuf, &outbuf_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_UPDATE_FAILED, "Updating of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
}

/* {{{ php_crypto_cipher_final */
static inline void php_crypto_cipher_final(INTERNAL_FUNCTION_PARAMETERS, int enc)
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
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(ENCRYPT_FINAL_STATUS, "Cipher object is not initialized for encryption");
		return;
	} else if (!enc && intern->status != PHP_CRYPTO_ALG_STATUS_DECRYPT) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DECRYPT_FINAL_STATUS, "Cipher object is not initialized for decryption");
		return;
	}
	
	outbuf_len = EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));
	
	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(intern->cipher.ctx, outbuf, &outbuf_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_FINAL_FAILED, "Finalizing of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf[outbuf_len] = 0;
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
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

	outbuf_len = data_len + EVP_CIPHER_block_size(intern->cipher.alg);
	outbuf = emalloc((outbuf_len + 1) * sizeof(unsigned char));

	/* update encryption context */
	if (!EVP_CipherUpdate(intern->cipher.ctx, outbuf, &outbuf_update_len, (unsigned char *) data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_UPDATE_FAILED, "Updating of cipher failed");
		efree(outbuf);
		return;
	}
	/* finalize encryption context */
	if (!EVP_CipherFinal_ex(intern->cipher.ctx, outbuf + outbuf_update_len, &outbuf_final_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(CIPHER_FINAL_FAILED, "Finalizing of cipher failed");
		efree(outbuf);
		return;
	}
	outbuf_len = outbuf_update_len + outbuf_final_len;
	outbuf[outbuf_len] = 0;
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;
	RETURN_STRINGL(outbuf, outbuf_len, 0);
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

/* {{{ proto string Crypto\Cipher::encryptFinal()
   Finalizes cipher encryption */
PHP_CRYPTO_METHOD(Cipher, encryptFinal)
{
	php_crypto_cipher_final(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
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

/* {{{ proto string Crypto\Cipher::decryptFinal()
   Finalizes cipher decryption */
PHP_CRYPTO_METHOD(Cipher, decryptFinal)
{
	php_crypto_cipher_final(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
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
	RETURN_LONG(EVP_CIPHER_block_size(intern->cipher.alg));
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
	RETURN_LONG(EVP_CIPHER_key_length(intern->cipher.alg));
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
	RETURN_LONG(EVP_CIPHER_iv_length(intern->cipher.alg));
}

/* {{{ proto static bool Crypto\Digest::hasAlgorithm(string $algorithm)
   Finds out whether algorithm exists */
PHP_CRYPTO_METHOD(Digest, hasAlgorithm)
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

/* {{{ proto Crypto\Digest::__construct(string $algorithm)
   Message Digest constructor */
PHP_CRYPTO_METHOD(Digest, __construct)
{
	php_crypto_algorithm_object *intern;
	char *algorithm;
	int algorithm_len;
	const EVP_MD *digest;
	
	intern = php_crypto_get_algorithm_object(&algorithm, &algorithm_len, INTERNAL_FUNCTION_PARAM_PASSTHRU);
	if (!intern) {
		return;
	}
	
	digest = EVP_get_digestbyname(algorithm);
	if (digest) {
		intern->digest.alg = digest;
	}
	else {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION_EX(DIGEST_NOT_FOUND, "Message Digest '%s' algorithm not found", algorithm);
	}
}
/* }}} */

/* {{{ php_crypto_digest_init_ex */
static inline php_crypto_algorithm_object *php_crypto_digest_init_ex(zval *zobject TSRMLS_DC)
{
	php_crypto_algorithm_object *intern = (php_crypto_algorithm_object *) zend_object_store_get_object(zobject TSRMLS_CC);
	
	/* initialize digest */
	if (!EVP_DigestInit_ex(intern->digest.ctx, intern->digest.alg, NULL)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DIGEST_INIT_FAILED, "Initialization of digest failed");
		return NULL;
	}
	intern->status = PHP_CRYPTO_ALG_STATUS_DIGEST;
	return intern;
}
/* }}} */

/* {{{ php_crypto_digest_init */
static inline php_crypto_algorithm_object *php_crypto_digest_init(INTERNAL_FUNCTION_PARAMETERS)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	
	php_crypto_digest_init_ex(getThis() TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_digest_update_ex */
static inline zend_bool php_crypto_digest_update_ex(php_crypto_algorithm_object *intern, char *data, int data_len TSRMLS_DC)
{
	/* check algorithm status */
	if (intern->status != PHP_CRYPTO_ALG_STATUS_DIGEST) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DIGEST_UPDATE_STATUS, "Digest object is not initialized");
		return FAILURE;
	}

	/* update digest context */
	if (!EVP_DigestUpdate(intern->digest.ctx, data, data_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DIGEST_UPDATE_FAILED, "Updating of digest failed");
		return FAILURE;
	}
	
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_digest_update */
static inline void php_crypto_digest_update(INTERNAL_FUNCTION_PARAMETERS)
{
	php_crypto_algorithm_object *intern;
	char *data;
	int data_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	php_crypto_digest_update_ex(intern, data, data_len TSRMLS_CC);
}
/* }}} */

/* {{{ php_crypto_digest_final */
static inline char *php_crypto_digest_final_ex(php_crypto_algorithm_object *intern TSRMLS_DC)
{
	unsigned char digest_value[EVP_MAX_MD_SIZE+1];
	int digest_len;

	/* check algorithm status */
	if (intern->status != PHP_CRYPTO_ALG_STATUS_DIGEST) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DIGEST_FINAL_STATUS, "Digest object is not initialized");
		return NULL;
	}

	/* finalize digest context */
	if (!EVP_DigestFinal(intern->digest.ctx, digest_value, &digest_len)) {
		PHP_CRYPTO_THROW_ALGORITHM_EXCEPTION(DIGEST_FINAL_FAILED, "Finalizing of digest failed");
		return NULL;
	}
	digest_value[digest_len] = 0;
	intern->status = PHP_CRYPTO_ALG_STATUS_CLEAR;
	return estrdup(digest_value);
}
/* }}} */

/* {{{ php_crypto_digest_final */
static inline void php_crypto_digest_final(INTERNAL_FUNCTION_PARAMETERS)
{
	php_crypto_algorithm_object *intern;
	char *digest;
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	digest = php_crypto_digest_final_ex(intern TSRMLS_CC);
	if (digest) {
		RETURN_STRING(digest, 0);
	}
}

/* {{{ php_crypto_digest_make */
static inline void php_crypto_digest_make(INTERNAL_FUNCTION_PARAMETERS)
{
	php_crypto_algorithm_object *intern;
	char *data, *digest;
	int data_len;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE) {
		return;
	}

	intern = php_crypto_digest_init_ex(getThis() TSRMLS_CC);
	if (intern == NULL) {
		return;
	}
	
	if (php_crypto_digest_update_ex(intern, data, data_len TSRMLS_CC) == FAILURE) {
		return;
	}

	digest = php_crypto_digest_final_ex(intern TSRMLS_CC);
	if (digest) {
		RETURN_STRING(digest, 0);
	}
}
/* }}} */

/* {{{ proto void Crypto\Digest::init()
   Initializes digest */
PHP_CRYPTO_METHOD(Digest, init)
{
	php_crypto_digest_init(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* {{{ proto void Crypto\Digest::update(string $data)
   Updates digest */
PHP_CRYPTO_METHOD(Digest, update)
{
	php_crypto_digest_update(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* {{{ proto string Crypto\Digest::final()
   Finalizes digest */
PHP_CRYPTO_METHOD(Digest, final)
{
	php_crypto_digest_final(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* {{{ proto string Crypto\Digest::make(string $data)
   Makes digest */
PHP_CRYPTO_METHOD(Digest, make)
{
	php_crypto_digest_make(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* {{{ proto int Crypto\Digest::getBlockSize()
   Returns digest block size */
PHP_CRYPTO_METHOD(Digest, getBlockSize)
{
	php_crypto_algorithm_object *intern;
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_MD_block_size(intern->digest.alg));
}

/* {{{ proto int Crypto\Digest::getSize()
   Returns digest size */
PHP_CRYPTO_METHOD(Digest, getSize)
{
	php_crypto_algorithm_object *intern;
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	intern = (php_crypto_algorithm_object *) zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(EVP_MD_size(intern->digest.alg));
}
