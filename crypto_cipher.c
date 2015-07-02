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

#define PHPC_SMART_CSTR_INCLUDE 1

#include "php.h"
#include "php_crypto.h"
#include "php_crypto_cipher.h"
#include "zend_exceptions.h"
#include "ext/standard/php_string.h"

#include <openssl/evp.h>

/* ERRORS */

PHP_CRYPTO_EXCEPTION_DEFINE(Cipher)
PHP_CRYPTO_ERROR_INFO_BEGIN(Cipher)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	ALGORITHM_NOT_FOUND,
	"Cipher '%s' algorithm not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_NOT_FOUND,
	"Cipher static method '%s' not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	STATIC_METHOD_TOO_MANY_ARGS,
	"Cipher static method %s can accept max two arguments"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	MODE_NOT_FOUND,
	"Cipher mode not found"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	MODE_NOT_AVAILABLE,
	"Cipher mode %s is not available in installed OpenSSL library"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AUTHENTICATION_NOT_SUPPORTED,
	"The authentication is not supported for %s cipher mode"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	KEY_LENGTH_INVALID,
	"Invalid length of key for cipher '%s' algorithm "
	"(required length: %d)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	IV_LENGTH_INVALID,
	"Invalid length of initial vector for cipher '%s' algorithm "
	"(required length: %d)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_SETTER_FORBIDDEN,
	"AAD setter has to be called before encryption or decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_SETTER_FAILED,
	"AAD setter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	AAD_LENGTH_HIGH,
	"AAD length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_GETTER_FORBIDDEN,
	"Tag getter has to be called after encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_SETTER_FORBIDDEN,
	"Tag setter has to be called before decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_GETTER_FAILED,
	"Tag getter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_SETTER_FAILED,
	"Tag setter failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_LENGTH_LOW,
	"Tag length can't be lower than 32 bits (4 characters)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	TAG_LENGTH_HIGH,
	"Tag length can't exceed 128 bits (16 characters)"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_ALG_FAILED,
	"Initialization of cipher algorithm failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_CTX_FAILED,
	"Initialization of cipher context failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_ENCRYPT_FORBIDDEN,
	"Cipher object is already used for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INIT_DECRYPT_FORBIDDEN,
	"Cipher object is already used for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_FAILED,
	"Updating of cipher failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_ENCRYPT_FORBIDDEN,
	"Cipher object is not initialized for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	UPDATE_DECRYPT_FORBIDDEN,
	"Cipher object is not initialized for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_FAILED,
	"Finalizing of cipher failed"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_ENCRYPT_FORBIDDEN,
	"Cipher object is not initialized for encryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	FINISH_DECRYPT_FORBIDDEN,
	"Cipher object is not initialized for decryption"
)
PHP_CRYPTO_ERROR_INFO_ENTRY(
	INPUT_DATA_LENGTH_HIGH,
	"Input data length can't exceed max integer length"
)
PHP_CRYPTO_ERROR_INFO_END()


/* ARG INFOS */

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_algorithm, 0)
ZEND_ARG_INFO(0, algorithm)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_data, 0)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_crypto_cipher_list, 0, 0, 0)
ZEND_ARG_INFO(0, aliases)
ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_crypto_cipher_static, 0)
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


static const zend_function_entry php_crypto_cipher_object_methods[] = {
	PHP_CRYPTO_ME(
		Cipher, getAlgorithms,
		arginfo_crypto_cipher_list,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, hasAlgorithm,
		arginfo_crypto_algorithm,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, hasMode,
		arginfo_crypto_cipher_mode,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, __callStatic,
		arginfo_crypto_cipher_static,
		ZEND_ACC_STATIC|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, __construct,
		arginfo_crypto_cipher_construct,
		ZEND_ACC_CTOR|ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptInit,
		arginfo_crypto_cipher_init,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptUpdate,
		arginfo_crypto_cipher_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encryptFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, encrypt,
		arginfo_crypto_cipher_crypt,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptInit,
		arginfo_crypto_cipher_init,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptUpdate,
		arginfo_crypto_cipher_data,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decryptFinish,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, decrypt,
		arginfo_crypto_cipher_crypt,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getBlockSize,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getKeyLength,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getIVLength,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getMode,
		NULL,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, getTag,
		arginfo_crypto_cipher_get_tag,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, setTag,
		arginfo_crypto_cipher_set_tag,
		ZEND_ACC_PUBLIC
	)
	PHP_CRYPTO_ME(
		Cipher, setAAD,
		arginfo_crypto_cipher_set_aad,
		ZEND_ACC_PUBLIC
	)
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
			EVP_CTRL_GCM_SET_IVLEN,
			EVP_CTRL_GCM_SET_TAG, EVP_CTRL_GCM_GET_TAG)
#else
	PHP_CRYPTO_CIPHER_MODE_ENTRY_NOT_DEFINED(GCM)
#endif
#ifdef EVP_CIPH_CCM_MODE
	PHP_CRYPTO_CIPHER_MODE_ENTRY_EX(CCM, 1,
			EVP_CTRL_CCM_SET_IVLEN,
			EVP_CTRL_CCM_SET_TAG, EVP_CTRL_CCM_GET_TAG)
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

/* class entry */
PHP_CRYPTO_API zend_class_entry *php_crypto_cipher_ce;

/* object handler */
PHPC_OBJ_DEFINE_HANDLER_VAR(crypto_cipher);

