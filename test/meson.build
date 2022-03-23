tests = [
  'basic.test',
  'commandline.test',
  'executables.test',
  'import-export.test',
  'invite-join.test',
  'invite-offline.test',
  'invite-tinc-up.test',
  'scripts.test',
  'security.test',
  'variables.test',
]

if opt_crypto != 'nolegacy'
  tests += 'algorithms.test'
  tests += 'legacy-protocol.test'
endif

if os_name != 'windows'
  tests += 'sptps-basic.test'
endif

if os_name == 'linux'
  tests += 'ns-ping.test'
endif

exe_splice = executable(
  'splice',
  sources: 'splice.c',
  dependencies: deps_common,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

env = environment()
env.set('TINC_PATH', exe_tinc.full_path())
env.set('TINCD_PATH', exe_tincd.full_path())
env.set('SPTPS_TEST_PATH', exe_sptps_test.full_path())
env.set('SPTPS_KEYPAIR_PATH', exe_sptps_keypair.full_path())
env.set('SPLICE_PATH', exe_splice.full_path())
env.set('TESTLIB_PATH', src_root / 'test' / 'testlib.sh')

deps_test = [
  exe_tinc,
  exe_tincd,
  exe_splice,
  exe_sptps_test,
  exe_sptps_keypair,
]

test_wd = meson.current_build_dir()

foreach test_name : tests
  target = find_program(test_name, native: true)
  test(test_name,
       target,
       timeout: 5 * 60,
       env: env,
       depends: deps_test,
       workdir: test_wd)
endforeach

