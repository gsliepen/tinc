src_ed25519 = files(
  'ecdh.c',
  'ecdsa.c',
  'ecdsagen.c',
  'fe.c',
  'ge.c',
  'key_exchange.c',
  'keypair.c',
  'sc.c',
  'sha512.c',
  'sign.c',
  'verify.c',
)

lib_ed25519 = static_library(
  'ed25519',
  sources: src_ed25519,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

