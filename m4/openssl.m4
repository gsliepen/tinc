dnl Check to find the OpenSSL headers/libraries


AC_DEFUN(tinc_OPENSSL,
[
  AC_ARG_WITH(openssl,
    [  --with-openssl=DIR      OpenSSL library and headers prefix],
    [openssl_lib="$withval/lib"
     openssl_include="$withval/include"]
  )
  AC_CACHE_CHECK([for openssl headers], tinc_cv_openssl_include,
  [
    AC_ARG_WITH(openssl-include,
      [  --with-openssl-include=DIR OpenSSL headers directory],
      [tinc_cv_openssl_include="$withval"],
      [if test "x$openssl_include" = "x" ; then
         tinc_cv_openssl_include="none given"
       else
         tinc_cv_openssl_include=$openssl_include
       fi]
    )
  ])
  AC_CACHE_CHECK([for openssl libraries], tinc_cv_openssl_lib,
  [
    AC_ARG_WITH(openssl-lib,
      [  --with-openssl-lib=DIR  OpenSSL library directory],
      [tinc_cv_openssl_lib="$withval"],
      [if test "x$openssl_lib" = "x" ; then
         tinc_cv_openssl_lib="none given"
       else
         tinc_cv_openssl_lib=$openssl_lib
       fi]
    )
  ])

if test "$tinc_cv_openssl_lib" != "none given" ; then
  LIBS="$LIBS -L$tinc_cv_openssl_lib"
fi
if test "$tinc_cv_openssl_include" != "none given" ; then
  INCLUDES="$INCLUDES -I$tinc_cv_openssl_include"
fi

osi=found
AC_CHECK_HEADERS(evp.h rsa.h rand.h err.h sha.h,
[], [osi=none; break])

if test "$osi" = "none" ; then
  osi=found
  AC_CHECK_HEADERS(openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h,
  [], [osi=none; break])
fi


libcrypto=none

if test "$osi" = "found" ; then
  AC_CHECK_LIB(crypto, SHA1_version, [
    libcrypto=yes
  ])
fi

if test $libcrypto = none; then
cat <<EOF

It seems like OpenSSL is not installed on this system.  But perhaps
you need to supply the exact location of the headers and libraries.
You can try running configure with the --with-openssl=/DIRECTORY
parameter.  If you installed the headers and libraries in a different
location you can use --with-openssl-include=/DIR and
--with-openssl-lib=/DIR.

EOF

  AC_MSG_ERROR(OpenSSL not found.)

else
  LIBS="$LIBS -lcrypto"
fi

])
