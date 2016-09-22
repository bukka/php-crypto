dnl $Id$
dnl config.m4 for extension crypto

PHP_ARG_WITH(crypto, for crypto support,
[  --with-crypto             Include crypto support])

if test "$PHP_CRYPTO" != "no"; then
  test -z "$PHP_OPENSSL" && PHP_OPENSSL=no
  if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
    dnl Try to find pkg-config
    if test -z "$PKG_CONFIG"; then
      AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
    fi
    dnl If pkg-config is found try using it
    if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists openssl; then
      OPENSSL_INCDIR=`$PKG_CONFIG --variable=includedir openssl`
      PHP_ADD_INCLUDE($OPENSSL_INCDIR)
      CRYPTO_LIBS=`$PKG_CONFIG --libs openssl`
      PHP_EVAL_LIBLINE($CRYPTO_LIBS, CRYPTO_SHARED_LIBADD)
    fi

    AC_DEFINE(HAVE_CRYPTOLIB,1,[Enable objective OpenSSL Crypto wrapper])
    PHP_SUBST(CRYPTO_SHARED_LIBADD)
    PHP_NEW_EXTENSION(crypto, 
      crypto.c \
	  crypto_object.c \
	  crypto_cipher.c \
	  crypto_hash.c \
	  crypto_kdf.c \
      crypto_base64.c \
      crypto_stream.c \
      crypto_rand.c,
      $ext_shared)
  fi
fi
