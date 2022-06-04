tests = [
  'address_cache.py',
  'basic.py',
  'bind_port.py',
  'cmd_dump.py',
  'cmd_fsck.py',
  'cmd_import.py',
  'cmd_join.py',
  'cmd_keys.py',
  'cmd_misc.py',
  'cmd_net.py',
  'cmd_sign_verify.py',
  'commandline.py',
  'device.py',
  'device_multicast.py',
  'executables.py',
  'import_export.py',
  'invite.py',
  'invite_tinc_up.py',
  'net.py',
  'proxy.py',
  'sandbox.py',
  'scripts.py',
  'security.py',
  'splice.py',
  'sptps_basic.py',
  'variables.py',
]

if opt_crypto != 'nolegacy'
  tests += [
    'algorithms.py',
    'legacy_protocol.py',
  ]
endif

if os_name == 'linux'
  tests += [
    'bind_address.py',
    'compression.py',
    'device_raw_socket.py',
    'device_tap.py',
    'ns_ping.py',
  ]
  if not opt_systemd.disabled()
    tests += 'systemd.py'
  endif
endif

if cdata.has('HAVE_FD_DEVICE')
  tests += 'device_fd.py'
endif

exe_splice = executable(
  'splice',
  sources: 'splice.c',
  dependencies: deps_common,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

env_vars = {
  'TINC_PATH': exe_tinc.full_path(),
  'TINCD_PATH': exe_tincd.full_path(),
  'PYTHON_PATH': python_path,
  'SPLICE_PATH': exe_splice.full_path(),
  'SPTPS_TEST_PATH': exe_sptps_test.full_path(),
  'SPTPS_KEYPAIR_PATH': exe_sptps_keypair.full_path(),
}

deps_test = [
  exe_tinc,
  exe_tincd,
  exe_splice,
  exe_sptps_test,
  exe_sptps_keypair,
]

test_wd = meson.current_build_dir()
test_src = meson.current_source_dir()

foreach test_name : tests
  if meson_version.version_compare('>=0.52')
    env = environment(env_vars)
  else
    env = environment()
    foreach k, v : env_vars
      env.set(k, v)
    endforeach
  endif
  env.set('TEST_NAME', test_name)

  test(test_name,
       python,
       args: test_src / test_name,
       suite: 'integration',
       timeout: 60,
       env: env,
       depends: deps_test,
       workdir: test_wd)
endforeach

