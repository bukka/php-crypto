dnl $Id$
dnl config.m4 for extension crypto

PHP_ARG_WITH(crypto, for crypto support,
[  --with-crypto             Include crypto support])

if test "$PHP_CRYPTO" != "no"; then
  test -z "$PHP_OPENSSL" && PHP_OPENSSL=no
  if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
	AC_DEFINE(HAVE_CRYPTOLIB,1,[Whether you want objective crypto binding])
	PHP_SUBST(CRYPTO_SHARED_LIBADD)
	PHP_NEW_EXTENSION(crypto, crypto.c crypto_evp.c, $ext_shared)
  fi
fi
