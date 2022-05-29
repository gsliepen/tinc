check_headers += [
  'linux/if_tun.h',
  'linux/landlock.h',
  'netpacket/packet.h',
]

check_functions += 'recvmmsg'

src_tincd += files(
  'device.c',
  'event.c',
)

dep_libsystemd = dependency('libsystemd', required: opt_systemd)
if dep_libsystemd.found()
  src_tincd += files('watchdog.c')
  deps_tincd += dep_libsystemd
  cdata.set('HAVE_WATCHDOG', 1)
endif

if opt_uml
  src_tincd += files('uml_device.c')
  cdata.set('ENABLE_UML', 1)
endif

seccomp_tested = ['x86_64', 'aarch64']

if opt_sandbox.enabled() or (opt_sandbox.auto() and cpu_family in seccomp_tested)
  dep_seccomp = dependency('libseccomp', required: opt_sandbox)
  if dep_seccomp.found()
    if cpu_family not in seccomp_tested
      warning('seccomp-bpf on ' + cpu_family + ' is untested, use at your own risk')
    endif
    src_tincd += files('tincd.c')
    deps_tincd += dep_seccomp
    src_tinc += files('../sandbox.c')
    cdata.set('HAVE_SANDBOX', 1)
  endif
endif

if cc.has_header('linux/landlock.h')
  src_tincd += files('landlock.c')
endif
