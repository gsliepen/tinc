dep_tunemu = dependency('tunemu', required: opt_tunemu, static: static)
dep_pcap = dependency('pcap', required: opt_tunemu, static: static)
dep_vmnet = dependency('vmnet', required: opt_vmnet, static: static)

if dep_tunemu.found() and dep_pcap.found()
  deps_tincd += [dep_tunemu, dep_pcap]
  src_tincd += files('tunemu.c')
  cdata.set('ENABLE_TUNEMU', 1)
endif

if dep_vmnet.found()
  deps_tincd += [dep_vmnet]
  src_tincd += files('vmnet.c')
  cdata.set('ENABLE_VMNET', 1)
endif

# macOS apparently doesn't support kqueue with TAP devices
src_tincd += src_event_select
