dnl Check to find the OpenSSL headers/libraries


AC_DEFUN(tinc_OPENSSL,
[

  AC_CACHE_CHECK([for openssl], tinc_cv_openssl_include,
  [
    AC_ARG_WITH(openssl,
      [  --with-openssl=DIR      OpenSSL library and headers prefix],
      [echo -ne 'prefix...'
       openssl_lib="$withval/lib"
       openssl_include="$withval/include"]
    )
    AC_ARG_WITH(openssl-include,
      [  --with-openssl-include=DIR OpenSSL headers directory],
      [echo -ne 'includes...'
       openssl_include="$withvall"]
    )
    AC_ARG_WITH(openssl-lib,
      [  --with-openssl-lib=DIR  OpenSSL library directory],
      [echo -ne 'libraries...'
       openssl_lib="$withval"]
    )

if test "x$openssl_lib" != "x" ; then
  LIBS="$LIBS -L$openssl_lib"
fi
if test "x$openssl_include" != "x" ; then
  INCLUDES="$INCLUDES -I$openssl_include"
fi

AC_MSG_RESULT([done.])
  ])

libcrypto=none
AC_CHECK_LIB(crypto, SHA1_version, [
  libcrypto=yes
])

if test $libcrypto = none; then
  AC_MSG_ERROR(
[It seems like OpenSSL is not installed on this system.  But perhaps
you need to supply the exact location of the headers and libraries.
You can try running configure with the --with-openssl=/DIRECTORY
parameter.  If you installed the headers and libraries in a different
location you can use --with-openssl-include=/DIR and
--with-openssl-lib=/DIR.])

else
  LIBS="$LIBS -lcrypto"
fi

])
