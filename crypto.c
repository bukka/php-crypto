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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_crypto.h"
#include "php_crypto_hash.h"
#include "php_crypto_cipher.h"
#include "php_crypto_base64.h"
#include "php_crypto_stream.h"
#include "php_crypto_rand.h"
#include "php_crypto_kdf.h"

#include <openssl/evp.h>

ZEND_DECLARE_MODULE_GLOBALS(crypto)

/* {{{ crypto_functions[] */
const zend_function_entry crypto_functions[] = {
	PHPC_FE_END
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
	PHP_MODULE_GLOBALS(crypto),
	PHP_GINIT(crypto),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_CRYPTO
ZEND_GET_MODULE(crypto)
#endif

/* Base exception */
PHP_CRYPTO_EXCEPTION_DEFINE(Crypto)

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(crypto)
{
	zend_class_entry ce;

	/* Register base exception */
	PHP_CRYPTO_EXCEPTION_REGISTER_CE(ce, Crypto, zend_exception_get_default(TSRMLS_C));

	/* Init OpenSSL algorithms */
	OpenSSL_add_all_algorithms();

#if PHP_CRYPTO_ADD_CCM_ALGOS
	EVP_add_cipher(EVP_aes_128_ccm());
	EVP_add_cipher(EVP_aes_192_ccm());
	EVP_add_cipher(EVP_aes_256_ccm());
#endif

	PHP_MINIT(crypto_cipher)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_hash)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_base64)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_stream)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_rand)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_kdf)(INIT_FUNC_ARGS_PASSTHRU);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION(crypto)
{
	crypto_globals->error_action = PHP_CRYPTO_ERROR_ACTION_EXCEPTION;
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

/* {{{ php_crypto_str_size_to_int */
PHP_CRYPTO_API int php_crypto_str_size_to_int(
		phpc_str_size_t size_len, int *int_len)
{
	PHPC_SIZE_TO_INT_EX(size_len, *int_len, return FAILURE);
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_long_to_int */
PHP_CRYPTO_API int php_crypto_long_to_int(
		phpc_long_t plv, int *lv)
{
	PHPC_LONG_TO_INT_EX(plv, *lv, return FAILURE);
	return SUCCESS;
}
/* }}} */

/* {{{ php_crypto_verror */
PHP_CRYPTO_API void php_crypto_verror(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC, const char *name, va_list args)
{
	const php_crypto_error_info *ei = NULL;
	char *message = NULL;
	long code = 1;

	if (action == PHP_CRYPTO_ERROR_ACTION_GLOBAL) {
		action = PHP_CRYPTO_G(error_action);
	} else if (action == PHP_CRYPTO_ERROR_ACTION_SILENT) {
		return;
	}

	while (info->name != NULL) {
		if (*info->name == *name && !strncmp(info->name, name, strlen(info->name))) {
			ei = info;
			break;
		}
		info++;
		code++;
	}

	if (!ei) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid error message");
		return;
	}
	switch (action) {
		case PHP_CRYPTO_ERROR_ACTION_ERROR:
			php_verror(NULL, "", ei->level, PHP_CRYPTO_GET_ERROR_MESSAGE(ei->msg, message), args TSRMLS_CC);
			break;
		case PHP_CRYPTO_ERROR_ACTION_EXCEPTION:
			if (ignore_args) {
				zend_throw_exception(exc_ce, PHP_CRYPTO_GET_ERROR_MESSAGE(ei->msg, message), code TSRMLS_CC);
			} else {
				vspprintf(&message, 0, ei->msg, args);
				zend_throw_exception(exc_ce, message, code TSRMLS_CC);
			}
			break;
		default:
			return;
	}
	if (message) {
		efree(message);
	}
}
/* }}} */

/* {{{ php_crypto_error_ex */
PHP_CRYPTO_API void php_crypto_error_ex(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC, const char *name, ...)
{
	va_list args;
	va_start(args, name);
	php_crypto_verror(info, exc_ce, action, ignore_args TSRMLS_CC, name, args);
	va_end(args);
}
/* }}} */

/* {{{ php_crypto_error */
PHP_CRYPTO_API void php_crypto_error(const php_crypto_error_info *info, zend_class_entry *exc_ce,
		php_crypto_error_action action, int ignore_args TSRMLS_DC, const char *name)
{
	php_crypto_error_ex(info, exc_ce, action, 1 TSRMLS_CC, name);
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
