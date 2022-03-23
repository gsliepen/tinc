src_chacha_poly = files(
  'chacha-poly1305.c',
  'chacha.c',
  'poly1305.c',
)

lib_chacha_poly = static_library(
  'chacha_poly',
  sources: src_chacha_poly,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

