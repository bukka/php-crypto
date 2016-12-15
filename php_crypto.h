/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2013-2016 Jakub Zelenka                                |
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

/* always inline even in debug mode */
#if defined(__GNUC__) && __GNUC__ >= 3
#define php_crypto_always_inline inline __attribute__((always_inline))
#else
#define php_crypto_always_inline inline
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include "php.h"
#include <openssl/evp.h>

/* PHP Compatibility layer */
#include "phpc/phpc.h"

/* Crypto version */
#define PHP_CRYPTO_VERSION "0.3.1"


/* NAMESPACE */

/* Crypto namespace name */
#define PHP_CRYPTO_NS_NAME "Crypto"

/* Namespace separator */
#define PHP_CRYPTO_NS_SEPARATOR "\\"

/* Crypto class name (including namespace) */
#define PHP_CRYPTO_CLASS_NAME(classname) \
	PHP_CRYPTO_NS_NAME PHP_CRYPTO_NS_SEPARATOR #classname

/* Crypto method definition */
#define PHP_CRYPTO_METHOD(classname, method) \
	PHP_METHOD(Crypto_##_##classname, method)

/* Crypto method entry */
#define PHP_CRYPTO_ME(classname, name, arg_info, flags) \
	PHP_ME(Crypto_##_##classname, name, arg_info, flags)

/* Crypto abstract method entry */
#define PHP_CRYPTO_ABSTRACT_ME(classname, name, arg_info) \
	PHP_ABSTRACT_ME(Crypto_##_##classname, name, arg_info)

/* Macros for dealing with Crypto sub namespaces (not used yet) */
#define PHP_CRYPTO_NS_NAMESPACE(ns) \
	PHP_CRYPTO_NS_NAME PHP_CRYPTO_NS_SEPARATOR #ns
#define PHP_CRYPTO_NS_CLASS_NAME(ns, classname) \
	PHP_CRYPTO_NS_NAMESPACE(ns) PHP_CRYPTO_NS_SEPARATOR #classname
#define PHP_CRYPTO_NS_METHOD(ns, classname, method) \
	PHP_METHOD(Crypto_##ns##_##classname, method)
#define PHP_CRYPTO_NS_ME(ns, classname, name, arg_info, flags) \
	PHP_ME(Crypto_##ns##_##classname, name, arg_info, flags)
#define PHP_CRYPTO_NS_ABSTRACT_ME(ns, classname, name, arg_info) \
	PHP_ABSTRACT_ME(Crypto_##ns##_##classname, name, arg_info)


/* NUMERIC CONVERSIONS */
PHP_CRYPTO_API int php_crypto_str_size_to_int(
		phpc_str_size_t size_len, int *int_len);
PHP_CRYPTO_API int php_crypto_long_to_int(
		phpc_long_t plv, int *lv);


/* ERROR TYPES */

/* Errors info structure */
typedef struct {
	const char *name;
	const char *msg;
	int level;
} php_crypto_error_info;

/* Error processing action */
typedef enum {
	PHP_CRYPTO_ERROR_ACTION_GLOBAL = 0,
	PHP_CRYPTO_ERROR_ACTION_SILENT,
	PHP_CRYPTO_ERROR_ACTION_EXCEPTION,
	PHP_CRYPTO_ERROR_ACTION_ERROR
} php_crypto_error_action;

/* Processes error msg and either throw exception,
 * emits error or do nothing (it depends on action) */
PHP_CRYPTO_API void php_crypto_verror(
		const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC,
		const char *name, va_list args);
/* Main error function with arguments */
PHP_CRYPTO_API void php_crypto_error_ex(
		const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC,
		const char *name, ...);
/* Main error function without arguments */
PHP_CRYPTO_API void php_crypto_error(
		const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC,
		const char *name);

/* Macros for crypto exceptions info */

#define PHP_CRYPTO_EXCEPTION_CE(ename) \
	php_crypto_##ename##Exception_ce

#define PHP_CRYPTO_EXCEPTION_EXPORT(ename) \
	extern PHP_CRYPTO_API zend_class_entry *PHP_CRYPTO_EXCEPTION_CE(ename);

#define PHP_CRYPTO_EXCEPTION_DEFINE(ename) \
	PHP_CRYPTO_API zend_class_entry *PHP_CRYPTO_EXCEPTION_CE(ename);

#define PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, ename, epname_ce) \
	INIT_CLASS_ENTRY(ce, PHP_CRYPTO_CLASS_NAME(ename ## Exception), NULL); \
	PHP_CRYPTO_EXCEPTION_CE(ename) = PHPC_CLASS_REGISTER_EX(ce, epname_ce, NULL)

#define PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, ename, epname) \
	PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, ename, PHP_CRYPTO_EXCEPTION_CE(epname))

#define PHP_CRYPTO_EXCEPTION_REGISTER(ce, ename) \
	PHP_CRYPTO_EXCEPTION_REGISTER_EX(ce, ename, Crypto)

/* Macros for error info */

#define PHP_CRYPTO_ERROR_INFO_NAME(ename) \
	php_crypto_error_info_##ename

#define PHP_CRYPTO_ERROR_INFO_BEGIN(ename) \
	php_crypto_error_info PHP_CRYPTO_ERROR_INFO_NAME(ename)[] = {

#define PHP_CRYPTO_ERROR_INFO_ENTRY_EX(einame, eimsg, eilevel) \
	{ #einame, eimsg, eilevel },

#define PHP_CRYPTO_ERROR_INFO_ENTRY(einame, eimsg) \
	PHP_CRYPTO_ERROR_INFO_ENTRY_EX(einame, eimsg, E_WARNING)

#define PHP_CRYPTO_ERROR_INFO_END() \
	{ NULL, NULL, 0} };
#define PHP_CRYPTO_ERROR_INFO_EXPORT(ename) \
		extern php_crypto_error_info PHP_CRYPTO_ERROR_INFO_NAME(ename)[];

#define PHP_CRYPTO_ERROR_INFO_REGISTER(ename) do { \
	long code = 1; \
	php_crypto_error_info *einfo = PHP_CRYPTO_ERROR_INFO_NAME(ename); \
	while (einfo->name != NULL) { \
		zend_declare_class_constant_long(PHP_CRYPTO_EXCEPTION_CE(ename), \
			einfo->name, strlen(einfo->name), code++ TSRMLS_CC); \
		einfo++; \
	} } while(0)

/* Macros for wrapping error arguments passed to php_crypto_error* */

#define PHP_CRYPTO_ERROR_ARGS_EX(ename, eexc, eact, einame) \
	PHP_CRYPTO_ERROR_INFO_NAME(ename), eexc, eact, 0 TSRMLS_CC, #einame

#define PHP_CRYPTO_ERROR_ARGS(ename, einame) \
	PHP_CRYPTO_ERROR_ARGS_EX(ename, PHP_CRYPTO_EXCEPTION_CE(ename), \
		PHP_CRYPTO_ERROR_ACTION_GLOBAL, einame)

/* Base exception class */
PHP_CRYPTO_EXCEPTION_EXPORT(Crypto)


/* GLOBALS */

ZEND_BEGIN_MODULE_GLOBALS(crypto)
	php_crypto_error_action error_action;  
ZEND_END_MODULE_GLOBALS(crypto)

#ifdef ZTS
# define PHP_CRYPTO_G(v) TSRMG(crypto_globals_id, zend_crypto_globals *, v)
#else
# define PHP_CRYPTO_G(v) (crypto_globals.v)
#endif


/* MODULE FUNCTIONS */

PHP_MINIT_FUNCTION(crypto);
PHP_GINIT_FUNCTION(crypto);
PHP_MSHUTDOWN_FUNCTION(crypto);
PHP_MINFO_FUNCTION(crypto);


/* COMPATIBILITY */

#define PHP_CRYPTO_COPY_ERROR_MESSAGE \
	(PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 5 && PHP_RELEASE_VERSION >= 5) \
	|| (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 6) \
	|| (PHP_MAJOR_VERSION > 5)

#if PHP_CRYPTO_COPY_ERROR_MESSAGE
#define PHP_CRYPTO_GET_ERROR_MESSAGE(const_msg, tmp_msg) \
	(const_msg)
#else
#define PHP_CRYPTO_GET_ERROR_MESSAGE(const_msg, tmp_msg) \
	(tmp_msg = estrdup(const_msg))
#endif

/* OpenSSL features test */
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
#define PHP_CRYPTO_HAS_CMAC 1
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define PHP_CRYPTO_HAS_CIPHER_CTX_COPY 1
#endif

#define PHP_CRYPTO_ADD_CCM_ALGOS \
	!defined(OPENSSL_NO_AES) && defined(EVP_CIPH_CCM_MODE) \
		&& OPENSSL_VERSION_NUMBER < 0x100020000

#endif	/* PHP_CRYPTO_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
