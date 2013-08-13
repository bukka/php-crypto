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

#define PHP_CRYPTO_NS_SEPARATOR "\\"
#define PHP_CRYPTO_NS_NAME(ns) "Crypto" PHP_CRYPTO_NS_SEPARATOR #ns
#define PHP_CRYPTO_CLASS_NAME(ns, classname) PHP_CRYPTO_NS_NAME(ns) PHP_CRYPTO_NS_SEPARATOR #classname
#define PHP_CRYPTO_METHOD(ns, classname, method) PHP_METHOD(Crypto_##ns##_##classname, method)
#define PHP_CRYPTO_ME(ns, classname, name, arg_info, flags) PHP_ME(Crypto_##ns##_##classname, name, arg_info, flags)
#define PHP_CRYPTO_ABSTRACT_ME(ns, classname, name, arg_info) PHP_ABSTRACT_ME(Crypto_##ns##_##classname, name, arg_info)

/* macros for throwing exceptions */
#define PHP_CRYPTO_THROW_EXCEPTION(exc_ce, code, msg) zend_throw_exception(exc_ce, msg, code TSRMLS_CC)
#define PHP_CRYPTO_THROW_EXCEPTION_EX(exc_ce, code, msg, ...) zend_throw_exception_ex(exc_ce, code TSRMLS_CC, msg, ##__VA_ARGS__)

#endif	/* PHP_CRYPTO_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
