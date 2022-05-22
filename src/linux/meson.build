check_headers += [
  'linux/if_tun.h',
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

