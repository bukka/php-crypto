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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_crypto.h"
#include "php_crypto_alg.h"
#include "php_crypto_base64.h"
#include "php_crypto_stream.h"
#include "php_crypto_rand.h"

#include <openssl/evp.h>


/* {{{ crypto_functions[] */
const zend_function_entry crypto_functions[] = {
	PHP_CRYPTO_FE_END
};
/* }}} */

/* {{{ crypto_module_entry
 */
zend_module_entry crypto_module_entry = {
	STANDARD_MODULE_HEADER,
	"crypto",
	crypto_functions,
	PHP_MINIT(crypto),
	PHP_MSHUTDOWN(crypto),
	NULL,
	NULL,
	PHP_MINFO(crypto),
	PHP_CRYPTO_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_CRYPTO
ZEND_GET_MODULE(crypto)
#endif

/* Base exception */
PHP_CRYPTO_EXCEPTION_DEFINE(Crypto);

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(crypto)
{
	zend_class_entry ce;
	
	/* Register base exception */
	PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, Crypto, zend_exception_get_default(TSRMLS_C));
	
	/* Init OpenSSL algorithms */
	OpenSSL_add_all_algorithms();
	
	PHP_MINIT(crypto_alg)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_base64)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_stream)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_rand)(INIT_FUNC_ARGS_PASSTHRU);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(crypto)
{
	PHP_MSHUTDOWN(crypto_stream)(SHUTDOWN_FUNC_ARGS_PASSTHRU);
	
	EVP_cleanup();
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(crypto)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Crypto Support", "enabled");
	php_info_print_table_row(2, "Crypto Version", PHP_CRYPTO_VERSION);
	php_info_print_table_row(2, "OpenSSL Library Version", SSLeay_version(SSLEAY_VERSION));
	php_info_print_table_row(2, "OpenSSL Header Version", OPENSSL_VERSION_TEXT);
	php_info_print_table_end();
}
/* }}} */

/* {{{ php_crypto_error_info_get */
static const php_crypto_error_info *php_crypto_error_info_find(const php_crypto_error_info *info, const char *name)
{
	while (info->name != NULL) {
		if (*info->name == *name && !strncmp(info->name, name, strlen(info->name))) {
			return info;
		}
		info++;
	}
	return NULL;
}

/* {{{ php_crypto_verror */
PHP_CRYPTO_API void php_crypto_verror(const php_crypto_error_info *info, zend_class_entry *exc_ce, 
		int ignore_args TSRMLS_DC, php_crypto_error_action action, const char *name, va_list args)
{
	const php_crypto_error_info *ei = php_crypto_error_info_find(info, name);
	if (!ei) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid error message");
		return;
	}
	switch (action) {
		case PHP_CRYPTO_ERROR_ACTION_ERROR:
			php_verror(NULL, "", ei->level, ei->msg, args TSRMLS_CC);
			break;
		case PHP_CRYPTO_ERROR_ACTION_EXCEPTION:
			if (ignore_args) {
				zend_throw_exception(exc_ce, ei->msg, ei->code TSRMLS_CC);
			} else {
				char *message;
				vspprintf(&message, 0, ei->msg, args);
				zend_throw_exception(exc_ce, message, ei->code TSRMLS_CC);
				efree(message);
			}
			break;
		default:
			break;
	}
}
/* }}} */

/* {{{ php_crypto_error_ex */
PHP_CRYPTO_API void php_crypto_error_ex(const php_crypto_error_info *info, zend_class_entry *exc_ce, 
		int ignore_args TSRMLS_DC, const char *name, ...)
{
	va_list args;
	va_start(args, name);
	php_crypto_verror(info, exc_ce, ignore_args TSRMLS_CC, PHP_CRYPTO_ERROR_ACTION_EXCEPTION, name, args);
	va_end(args);
}
/* }}} */

/* {{{ php_crypto_error */
PHP_CRYPTO_API void php_crypto_error(const php_crypto_error_info *info, zend_class_entry *exc_ce, 
		int ignore_args TSRMLS_DC, const char *name)
{
	php_crypto_error_ex(info, exc_ce, 1 TSRMLS_CC, name);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
