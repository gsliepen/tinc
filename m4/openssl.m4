dnl Check to find the OpenSSL headers/libraries

AC_DEFUN(tinc_OPENSSL,
[
  tinc_ac_save_CPPFLAGS="$CPPFLAGS"

  AC_ARG_WITH(openssl,
    AC_HELP_STRING([--with-openssl=DIR], [OpenSSL base directory, or:]),
    [openssl="$withval"
     CFLAGS="$CFLAGS -I$withval/include"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LIBS="$LIBS -L$withval/lib"]
  )

  AC_ARG_WITH(openssl-include,
    AC_HELP_STRING([--with-openssl-include=DIR], [OpenSSL headers directory (without trailing /openssl)]),
    [openssl_include="$withval"
     CFLAGS="$CFLAGS -I$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(openssl-lib,
    AC_HELP_STRING([--with-openssl-lib=DIR], [OpenSSL library directory]),
    [openssl_lib="$withval"
     LIBS="$LIBS -L$withval"]
  )

  AC_CHECK_HEADERS(openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h openssl/pem.h,
    [],
    [AC_MSG_ERROR([OpenSSL header files not found.]); break]
  )

  CPPFLAGS="$tinc_ac_save_CPPFLAGS"

case $host_os in
  *mingw*)
    AC_CHECK_LIB(crypto, SHA1_version,
      [LIBS="$LIBS -lcrypto -lgdi32"],
      [AC_MSG_ERROR([OpenSSL libraries not found.])]
    )
  ;;
  *)
    AC_CHECK_LIB(crypto, SHA1_version,
      [LIBS="$LIBS -lcrypto"],
      [AC_MSG_ERROR([OpenSSL libraries not found.])]
    )

    AC_CHECK_FUNC(dlopen,
      [],
      [AC_CHECK_LIB(dl, dlopen,
        [LIBS="$LIBS -ldl"],
        [AC_MSG_ERROR([OpenSSL depends on libdl.]); break]
      )]
    )
  ;;
esac

  AC_CHECK_FUNCS([RAND_pseudo_bytes EVP_EncryptInit_ex], ,
    [AC_MSG_ERROR([Missing OpenSSL functionality, make sure you have installed the latest version.]); break],
  )

  AC_CHECK_DECL([OpenSSL_add_all_algorithms], ,
    [AC_MSG_ERROR([Missing OpenSSL functionality, make sure you have installed the latest version.]); break],
    [#include <openssl/evp.h>]
  )
])
