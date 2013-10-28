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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_crypto.h"
#include "php_crypto_alg.h"
#include "php_crypto_base64.h"
#include "php_crypto_rand.h"


/* {{{ crypto_functions[] */
const zend_function_entry crypto_functions[] = {
	PHP_FE_END
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
	"0.1",
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_CRYPTO
ZEND_GET_MODULE(crypto)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(crypto)
{
	PHP_MINIT(crypto_alg)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_base64)(INIT_FUNC_ARGS_PASSTHRU);
	PHP_MINIT(crypto_rand)(INIT_FUNC_ARGS_PASSTHRU);
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(crypto)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(crypto)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Crypto support", "enabled");
	php_info_print_table_row(2, "OpenSSL Library Version", SSLeay_version(SSLEAY_VERSION));
	php_info_print_table_row(2, "OpenSSL Header Version", OPENSSL_VERSION_TEXT);
	php_info_print_table_end();
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
