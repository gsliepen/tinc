src_lib_crypto = files(
  'cipher.c',
  'crypto.c',
  'digest.c',
  'log.c',
  'prf.c',
  'rsa.c',
  'rsagen.c',
)

# OpenBSD's 'OpenSSL' is actually LibreSSL. pkg-config on OpenBSD 7.0 reports
# it as OpenSSL 1.0, but it has everything we need (unlike 'real' OpenSSL 1.0).

if os_name == 'openbsd'
  names = ['openssl', 'eopenssl30', 'eopenssl11']
  min_ver = '>=1.0.0'
else
  names = ['openssl', 'openssl11']
  min_ver = '>=1.1.0'
endif

if meson_version.version_compare('>=0.60')
  dep_crypto = dependency(names, version: min_ver, static: static)
else
  foreach name : names
    dep_crypto = dependency(name, version: min_ver, static: static, required: false)
    if dep_crypto.found()
      break
    endif
  endforeach
  if not dep_crypto.found()
    dep_crypto = dependency('', static: static, fallback: ['openssl', 'openssl_dep'])
  endif
endif

cdata.set('HAVE_OPENSSL', 1)

