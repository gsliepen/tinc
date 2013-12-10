dnl Check to find the libgcrypt headers/libraries

AC_DEFUN([tinc_LIBGCRYPT],
[
  AC_ARG_WITH(libgcrypt,
    AS_HELP_STRING([--with-libgcrypt=DIR], [libgcrypt base directory, or:]),
    [libgcrypt="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(libgcrypt-include,
    AS_HELP_STRING([--with-libgcrypt-include=DIR], [libgcrypt headers directory (without trailing /libgcrypt)]),
    [libgcrypt_include="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(libgcrypt-lib,
    AS_HELP_STRING([--with-libgcrypt-lib=DIR], [libgcrypt library directory]),
    [libgcrypt_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_HEADERS([gcrypt.h],
    [],
    [AC_MSG_ERROR([libgcrypt header files not found.]); break]
  )

  AC_CHECK_LIB(gcrypt, gcry_cipher_encrypt,
    [LIBS="-lgcrypt $LIBS"],
    [AC_MSG_ERROR([libgcrypt libraries not found.])]
  )
])
