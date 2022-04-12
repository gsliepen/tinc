check_headers += [
  'linux/if_tun.h',
  'netpacket/packet.h',
  'sys/epoll.h',
  'sys/random.h',
]

check_functions += [
  'recvmmsg',
  'getrandom',
]

src_tincd += files('device.c')

if opt_uml
  src_tincd += files('uml_device.c')
  cdata.set('ENABLE_UML', 1)
endif

