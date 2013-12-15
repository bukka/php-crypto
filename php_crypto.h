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

#ifndef PHP_CRYPTO_H
#define PHP_CRYPTO_H

extern zend_module_entry crypto_module_entry;
#define phpext_crypto_ptr &crypto_module_entry

#ifdef PHP_WIN32
#	define PHP_CRYPTO_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_CRYPTO_API __attribute__ ((visibility("default")))
#else
#	define PHP_CRYPTO_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(crypto);
PHP_MSHUTDOWN_FUNCTION(crypto);
PHP_MINFO_FUNCTION(crypto);

/* Macros for Crypto namespace */
#define PHP_CRYPTO_NS_NAME "Crypto"
#define PHP_CRYPTO_NS_SEPARATOR "\\"
/* Macros for dealing with Crypto namespace classes */
#define PHP_CRYPTO_CLASS_NAME(classname) PHP_CRYPTO_NS_NAME PHP_CRYPTO_NS_SEPARATOR #classname
#define PHP_CRYPTO_METHOD(classname, method) PHP_METHOD(Crypto_##_##classname, method)
#define PHP_CRYPTO_ME(classname, name, arg_info, flags) PHP_ME(Crypto_##_##classname, name, arg_info, flags)
#define PHP_CRYPTO_ABSTRACT_ME(classname, name, arg_info) PHP_ABSTRACT_ME(Crypto_##_##classname, name, arg_info)
/* Macros for dealing with Crypto sub namespaces */
#define PHP_CRYPTO_NS_NAMESPACE(ns) PHP_CRYPTO_NS_NAME PHP_CRYPTO_NS_SEPARATOR #ns
#define PHP_CRYPTO_NS_CLASS_NAME(ns, classname) PHP_CRYPTO_NS_NAMESPACE(ns) PHP_CRYPTO_NS_SEPARATOR #classname
#define PHP_CRYPTO_NS_METHOD(ns, classname, method) PHP_METHOD(Crypto_##ns##_##classname, method)
#define PHP_CRYPTO_NS_ME(ns, classname, name, arg_info, flags) PHP_ME(Crypto_##ns##_##classname, name, arg_info, flags)
#define PHP_CRYPTO_NS_ABSTRACT_ME(ns, classname, name, arg_info) PHP_ABSTRACT_ME(Crypto_##ns##_##classname, name, arg_info)

/* macros for throwing exceptions */
#define PHP_CRYPTO_THROW_EXCEPTION(exc_ce, code, msg) zend_throw_exception(exc_ce, msg, code TSRMLS_CC)
#define PHP_CRYPTO_THROW_EXCEPTION_EX(exc_ce, code, msg, ...) zend_throw_exception_ex(exc_ce, code TSRMLS_CC, msg, ##__VA_ARGS__)

/* macro for initializing properties in obejct (new definition for PHP 5.3) */
#if PHP_VERSION_ID < 50399
#define PHP_CRYPTO_OBJECT_PROPERTIES_INIT(zo, class_type) { \
	zval *tmp; \
	zend_hash_copy((*(zo)).properties, \
		&(class_type)->default_properties, \
		(copy_ctor_func_t) zval_add_ref, \
		(void *) &tmp, \
		sizeof(zval *)); \
}
#define PHP_CRYPTO_PATH_FMT "s"
#else
#define PHP_CRYPTO_OBJECT_PROPERTIES_INIT(zo, class_type) object_properties_init(zo, class_type)
#define PHP_CRYPTO_PATH_FMT "p"
#endif

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 3 && PHP_RELEASE_VERSION >= 7) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 4) || (PHP_MAJOR_VERSION > 5)
#define PHP_CRYPTO_FE_END PHP_FE_END
#else
#define PHP_CRYPTO_FE_END {NULL,NULL,NULL}
#endif

/* OpenSSL features test */
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
#define PHP_CRYPTO_HAS_CMAC 1
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define PHP_CRYPTO_HAS_CIPHER_CTX_COPY 1
#define PHP_CRYPTO_HAS_HMAC_CTX_COPY 1
#endif

#endif	/* PHP_CRYPTO_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
