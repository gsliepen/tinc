check_headers += [
  'net/if_tap.h',
  'net/if_tun.h',
  'net/if_utun.h',
  'net/tap/if_tap.h',
  'net/tun/if_tun.h',
]

check_functions += [
  'devname',
  'fdevname',
]

src_tincd += files('device.c')

if os_name != 'darwin'
  src_tincd += files('event.c')
endif

if os_name in ['openbsd', 'darwin']
  subdir(os_name)
endif

