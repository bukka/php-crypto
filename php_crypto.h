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

/* Crypto version */
#define PHP_CRYPTO_VERSION "0.1.1"

/* Module macros */
PHP_MINIT_FUNCTION(crypto);
PHP_MSHUTDOWN_FUNCTION(crypto);
PHP_MINFO_FUNCTION(crypto);


/* NAMESPACE */

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

/* ERRORS */

/* Errors info structure */
typedef struct {
	const char *name;
	const char *msg;
	int level;
} php_crypto_error_info;

/* Error processing action */
typedef enum {
	PHP_CRYPTO_ERROR_ACTION_SILENT = 0,
	PHP_CRYPTO_ERROR_ACTION_EXCEPTION,
	PHP_CRYPTO_ERROR_ACTION_ERROR
} php_crypto_error_action;

/* Processes error msg and either throw exception, emits error or do nothing (it depends on action) */
PHP_CRYPTO_API void php_crypto_verror(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		int ignore_args TSRMLS_DC, php_crypto_error_action action, const char *name, va_list args);
/* Main error function with arguments */
PHP_CRYPTO_API void php_crypto_error_ex(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		int ignore_args TSRMLS_DC, const char *name, ...);
/* Main error function without arguments */
PHP_CRYPTO_API void php_crypto_error(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		int ignore_args TSRMLS_DC, const char *name);

/* Macros for crypto exceptions info */
#define PHP_CRYPTO_EXCEPTION_NAME(ename) php_crypto_##ename##Exception_ce
#define PHP_CRYPTO_EXCEPTION_EXPORT(ename) extern PHP_CRYPTO_API zend_class_entry *PHP_CRYPTO_EXCEPTION_NAME(ename);
#define PHP_CRYPTO_EXCEPTION_DEFINE(ename) PHP_CRYPTO_API zend_class_entry *PHP_CRYPTO_EXCEPTION_NAME(ename);
#define PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, ename, epname_ce) \
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(ename ## Exception), NULL); \
	PHP_CRYPTO_EXCEPTION_NAME(ename) = zend_register_internal_class_ex(&ce, epname_ce, NULL TSRMLS_CC)
#define PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, ename, epname) PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, ename, PHP_CRYPTO_EXCEPTION_NAME(epname))
#define PHP_CRYPTO_EXCEPTION_REGISTER(ce, ename) PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, ename, Crypto)

/* Macros for error info */
#define PHP_CRYPTO_ERROR_INFO_NAME(ename) php_crypto_error_info_##ename
#define PHP_CRYPTO_ERROR_INFO_BEGIN(ename) php_crypto_error_info PHP_CRYPTO_ERROR_INFO_NAME(ename)[] = {
#define PHP_CRYPTO_ERROR_INFO_ENTRY_EX(einame, eimsg, eilevel) { #einame, eimsg, eilevel },
#define PHP_CRYPTO_ERROR_INFO_ENTRY(einame, eimsg) PHP_CRYPTO_ERROR_INFO_ENTRY_EX(einame, eimsg, E_WARNING)
#define PHP_CRYPTO_ERROR_INFO_END() { NULL, NULL, 0} };
#define PHP_CRYPTO_ERROR_INFO_EXPORT(ename) extern php_crypto_error_info PHP_CRYPTO_ERROR_INFO_NAME(ename)[];
#define PHP_CRYPTO_ERROR_INFO_REGISTER(ename) do { \
	long code = 1; php_crypto_error_info *einfo = PHP_CRYPTO_ERROR_INFO_NAME(ename); \
	while (einfo->name != NULL) { \
		zend_declare_class_constant_long(PHP_CRYPTO_EXCEPTION_NAME(ename), einfo->name, strlen(einfo->name), code++ TSRMLS_CC); \
		einfo++; \
	} } while(0)

/* Macro for wrapping error arguments passed to php_crypto_error* */
#define PHP_CRYPTO_ERROR_ARGS(ename, einame) PHP_CRYPTO_ERROR_INFO_NAME(ename), PHP_CRYPTO_EXCEPTION_NAME(ename), 0 TSRMLS_CC, #einame

/* Base exception class */
PHP_CRYPTO_EXCEPTION_EXPORT(Crypto)


/* COMPATIBILITY */

/* Macro for initializing properties in obejct (new definition for PHP 5.3) */
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

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 5 && PHP_RELEASE_VERSION >= 5) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 6) || (PHP_MAJOR_VERSION > 5)
#define PHP_CRYPTO_GET_ERROR_MESSAGE(const_msg, tmp_msg) (const_msg)
#else
#define PHP_CRYPTO_GET_ERROR_MESSAGE(const_msg, tmp_msg) (tmp_msg = estrdup(const_msg))
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
