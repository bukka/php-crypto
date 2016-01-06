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

#include "php.h"
#include "php_crypto.h"
#include "php_crypto_object.h"

#include <openssl/objects.h>

/* do all parameter structure */
typedef struct {
	zend_bool aliases;
	char *prefix;
	phpc_str_size_t prefix_len;
	zval *return_value;
} php_crypto_object_do_all_param;

/* {{{ php_crypto_object_do_all */
static void php_crypto_object_do_all(const OBJ_NAME *name, void *arg)
{
	php_crypto_object_do_all_param *pp = (php_crypto_object_do_all_param *) arg;
	if ((pp->aliases || name->alias == 0) &&
			(!pp->prefix || !strncmp(name->name, pp->prefix, pp->prefix_len))) {
		PHPC_ARRAY_ADD_NEXT_INDEX_CSTR(pp->return_value, (char *) name->name);
	}
}
/* }}} */

/* {{{ php_crypto_object_fn_get_names */
PHP_CRYPTO_API void php_crypto_object_fn_get_names(INTERNAL_FUNCTION_PARAMETERS, int type)
{
	php_crypto_object_do_all_param param = { 0, NULL, 0, return_value };

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|bs",
			&param.aliases, &param.prefix, &param.prefix_len) == FAILURE) {
		return;
	}
	array_init(return_value);
	OBJ_NAME_do_all_sorted(type, php_crypto_object_do_all, &param);
}
/* }}} */
