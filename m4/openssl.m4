dnl Check to find the OpenSSL headers/libraries

AC_DEFUN(tinc_OPENSSL,
[
  tinc_ac_save_CPPFLAGS="$CPPFLAGS"

  AC_ARG_WITH(openssl-include,
    [  --with-openssl-include=DIR  OpenSSL headers directory (without trailing /openssl)],
    [openssl_include="$withval"
     CFLAGS="$CFLAGS -I$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(openssl-lib,
    [  --with-openssl-lib=DIR  OpenSSL library directory],
    [openssl_lib="$withval"
     LIBS="$LIBS -L$withval"]
  )

  AC_CHECK_HEADERS(openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h openssl/pem.h,
    [],
    [AC_MSG_ERROR("OpenSSL header files not found."); break]
  )

  CPPFLAGS="$tinc_ac_save_CPPFLAGS"

  AC_CHECK_LIB(crypto, SHA1_version,
    [LIBS="$LIBS -lcrypto"],
    [AC_MSG_ERROR("OpenSSL libraries not found.")]
  )

  AC_CHECK_FUNCS(RAND_pseudo_bytes)

  AC_CHECK_FUNC(OpenSSL_add_all_algorithms,
    [],
    AC_CHECK_FUNC(SSLeay_add_all_algorithms,
      [AC_DEFINE(HAVE_SSLEAY_ADD_ALL_ALGORITHMS)],
      [AC_MSG_ERROR("Missing required OpenSSL functionality!")]
    )
  )

  AC_CHECK_FUNC(dlopen,
    [],
    AC_CHECK_LIB(dl, dlopen,
      [LIBS="$LIBS -ldl"],
      [AC_MSG_ERROR("OpenSSL depends on libdl.")]
    )
  )
])
