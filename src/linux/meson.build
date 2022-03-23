check_headers += [
  'linux/if_tun.h',
  'sys/epoll.h',
  'netpacket/packet.h',
]

check_functions += 'recvmmsg'

src_tincd += files('device.c')

if opt_uml
  src_tincd += files('uml_device.c')
  cdata.set('ENABLE_UML', 1)
endif

