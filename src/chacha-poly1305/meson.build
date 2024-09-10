src_chacha_poly = files(
  'chacha-poly1305.c',
  'chacha.c',
  'poly1305.c',
)

chacha_impl = 'generic'
if cdata.has('HAVE_CPU_SSSE3')
  src_chacha_poly += files('chacha_ssse3.c')
  chacha_impl = 'SSSE3'
  if cdata.has('HAVE_CPU_AVX2')
    src_chacha_poly += files('chacha_avx2.c')
    chacha_impl = 'AVX2'
  endif
endif

if meson_version.version_compare('>=0.53')
  summary({ 'ChaCha20': chacha_impl }, section: 'Cryptography')
endif

lib_chacha_poly = static_library(
  'chacha_poly',
  sources: src_chacha_poly,
  implicit_include_directories: false,
  link_with: lib_cpu_features,
  include_directories: inc_conf,
  build_by_default: false,
)

if os_name != 'windows'
  exe_bench_chacha = executable(
    'bench_chacha',
    sources: files('../random.c', 'bench_chacha.c'),
    link_with: lib_chacha_poly,
    implicit_include_directories: false,
    include_directories: inc_conf,
    build_by_default: false,
  )

  benchmark('bench_chacha', exe_bench_chacha)
endif
