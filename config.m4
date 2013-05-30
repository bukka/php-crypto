dnl $Id$
dnl config.m4 for extension crypto

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(crypto, for crypto support,
dnl Make sure that the comment is aligned:
dnl [  --with-crypto             Include crypto support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(crypto, whether to enable crypto support,
dnl Make sure that the comment is aligned:
dnl [  --enable-crypto           Enable crypto support])

if test "$PHP_CRYPTO" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-crypto -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/crypto.h"  # you most likely want to change this
  dnl if test -r $PHP_CRYPTO/$SEARCH_FOR; then # path given as parameter
  dnl   CRYPTO_DIR=$PHP_CRYPTO
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for crypto files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       CRYPTO_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$CRYPTO_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the crypto distribution])
  dnl fi

  dnl # --with-crypto -> add include path
  dnl PHP_ADD_INCLUDE($CRYPTO_DIR/include)

  dnl # --with-crypto -> check for lib and symbol presence
  dnl LIBNAME=crypto # you may want to change this
  dnl LIBSYMBOL=crypto # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $CRYPTO_DIR/lib, CRYPTO_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_CRYPTOLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong crypto lib version or lib not found])
  dnl ],[
  dnl   -L$CRYPTO_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(CRYPTO_SHARED_LIBADD)

  PHP_NEW_EXTENSION(crypto, crypto.c, $ext_shared)
fi
