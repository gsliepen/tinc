src_lib_crypto = files(
  'cipher.c',
  'crypto.c',
  'digest.c',
  'pem.c',
  'prf.c',
  'rsa.c',
  'rsagen.c',
)

# Under current MinGW, flags specified in libgcrypt.pc fail on static build
if static and os_name == 'windows'
  dep_crypto = []
  foreach lib : ['libgcrypt', 'gpg-error']
    dep_crypto += cc.find_library(lib, static: true)
  endforeach
else
  dep_crypto = dependency('libgcrypt', static: static)
endif

cdata.set('HAVE_LIBGCRYPT', 1)

