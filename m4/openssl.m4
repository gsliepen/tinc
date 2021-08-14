dnl Check to find the LibreSSL/OpenSSL headers/libraries

AC_DEFUN([tinc_OPENSSL],
[
  case $host_os in
    *mingw*)
    ;;
    *)
      AC_CHECK_FUNC(dlopen,
        [],
        [AC_CHECK_LIB(dl, dlopen,
          [LIBS="$LIBS -ldl"],
          [AC_MSG_ERROR([LibreSSL/OpenSSL depends on libdl.]); break]
        )]
      )
    ;;
  esac

  AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl=DIR], [LibreSSL/OpenSSL base directory, or:]),
    [openssl="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(openssl-include,
    AS_HELP_STRING([--with-openssl-include=DIR], [LibreSSL/OpenSSL headers directory (without trailing /openssl)]),
    [openssl_include="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(openssl-lib,
    AS_HELP_STRING([--with-openssl-lib=DIR], [LibreSSL/OpenSSL library directory]),
    [openssl_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_HEADERS([openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h openssl/pem.h openssl/engine.h],
    [],
    [AC_MSG_ERROR([LibreSSL/OpenSSL header files not found.]); break]
  )

  AC_CHECK_LIB(crypto, OPENSSL_init_crypto,
    [LIBS="-lcrypto $LIBS"],
    [AC_MSG_ERROR([LibreSSL/OpenSSL libraries not found.])]
  )

  AC_DEFINE(HAVE_OPENSSL, 1, [enable OpenSSL support])
])
