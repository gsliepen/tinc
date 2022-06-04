inc_conf = include_directories('include')

cdata = configuration_data()

cdata.set_quoted('PACKAGE', meson.project_name())
cdata.set_quoted('VERSION', meson.project_version())
cdata.set_quoted('CONFDIR', dir_sysconf)
cdata.set_quoted('RUNSTATEDIR', dir_run_state)
cdata.set_quoted('LOCALSTATEDIR', dir_local_state)
cdata.set_quoted('SBINDIR', dir_sbin)

cdata.set('HAVE_' + os_name.to_upper(), 1)

foreach attr : ['malloc', 'nonnull', 'warn_unused_result', 'packed', 'format']
  if cc.has_function_attribute(attr)
    cdata.set('HAVE_ATTR_' + attr.to_upper(), 1,
              description: '__attribute__((__@0@__))'.format(attr))
  endif
endforeach

if cc.compiles('''
    #include <stdlib.h>
    extern void *make() __attribute__((malloc(free)));
    int main(void) { return 0; }
''')
  cdata.set('HAVE_ATTR_MALLOC_WITH_ARG', 1,
            description: 'support for __attribute__((malloc(deallocator)))')
endif

if cc.compiles('''
    _Static_assert(1, "ok");
    int main(void) { return 0; }
''')
  cdata.set('HAVE_STATIC_ASSERT', 1,
            description: 'C11 _Static_assert()')
endif

check_headers = [
  'alloca.h',
  'arpa/inet.h',
  'arpa/nameser.h',
  'dirent.h',
  'getopt.h',
  'inttypes.h',
  'net/ethernet.h',
  'net/if.h',
  'net/if_arp.h',
  'net/if_types.h',
  'netdb.h',
  'netinet/icmp6.h',
  'netinet/if_ether.h',
  'netinet/in.h',
  'netinet/in6.h',
  'netinet/in_systm.h',
  'netinet/ip.h',
  'netinet/ip6.h',
  'netinet/ip_icmp.h',
  'netinet/tcp.h',
  'resolv.h',
  'stddef.h',
  'sys/file.h',
  'sys/ioctl.h',
  'sys/mman.h',
  'sys/param.h',
  'sys/random.h',
  'sys/resource.h',
  'sys/socket.h',
  'sys/stat.h',
  'sys/time.h',
  'sys/types.h',
  'sys/wait.h',
  'syslog.h',
  'string.h',
  'termios.h',
  'unistd.h',
]

# 'struct msghdr' misses some required fields
if os_name != 'sunos'
  check_headers += 'sys/un.h'
endif

check_functions = [
  'asprintf',
  'daemon',
  'explicit_bzero',
  'explicit_memset',
  'fchmod',
  'getentropy',
  'gettimeofday',
  'memset_s',
  'mlockall',
  'putenv',
  'strsignal',
  'unsetenv',
]

# Broken definition, fails to link
if os_name != 'windows'
  check_functions += 'fork'
endif

check_types = [
  'struct arphdr',
  'struct ether_arp',
  'struct ether_header',
  'struct icmp',
  'struct icmp6_hdr',
  'struct ip',
  'struct ip6_hdr',
  'struct nd_neighbor_solicit',
  'struct nd_opt_hdr',
]

subdir('ed25519')
subdir('chacha-poly1305')

src_lib_common = [
  'conf.c',
  'console.c',
  'dropin.c',
  'fs.c',
  'keys.c',
  'list.c',
  'logger.c',
  'names.c',
  'netutl.c',
  'pidfile.c',
  'script.c',
  'splay_tree.c',
  'sptps.c',
  'subnet_parse.c',
  'utils.c',
  'version.c',
  'xoshiro.c',
]

src_tinc = [
  'fsck.c',
  'ifconfig.c',
  'info.c',
  'invitation.c',
  'top.c',
]

src_tincd = [
  'address_cache.c',
  'autoconnect.c',
  'buffer.c',
  'compression.h',
  'conf_net.c',
  'connection.c',
  'control.c',
  'dummy_device.c',
  'edge.c',
  'event.c',
  'graph.c',
  'meta.c',
  'multicast_device.c',
  'net.c',
  'net_packet.c',
  'net_setup.c',
  'net_socket.c',
  'node.c',
  'process.c',
  'protocol.c',
  'protocol_auth.c',
  'protocol_edge.c',
  'protocol_key.c',
  'protocol_misc.c',
  'protocol_subnet.c',
  'proxy.c',
  'raw_socket_device.c',
  'route.c',
  'subnet.c',
]

src_event_select = files('event_select.c')

if os_name != 'windows'
  src_tincd += 'signal.c'
endif

cc_flags_tinc = cc_flags
cc_flags_tincd = cc_flags

deps_common = []
deps_tinc = []
deps_tincd = [cc.find_library('m', required: false)]

if os_name != 'windows'
  src_lib_common += 'random.c'
endif

if os_name in ['linux', 'android']
  subdir('linux')
elif os_name.endswith('bsd') or os_name in ['dragonfly', 'darwin']
  subdir('bsd')
elif os_name == 'sunos'
  subdir('solaris')
elif os_name == 'windows'
  subdir('windows')
endif

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.to_upper().underscorify(),
              1,
              description: '#include <' + h + '>')
  endif
endforeach

if cdata.has('HAVE_SYS_UN_H')
  src_tincd += 'fd_device.c'
  cdata.set('HAVE_FD_DEVICE', 1)
endif

confdata = configuration_data()
confdata.merge_from(cdata)
configure_file(output: 'meson_config.h', configuration: confdata)

have_prefix = '''
  #include "@0@/src/meson_config.h"
  #include "@1@/have.h"
'''.format(build_root, meson.current_source_dir())

foreach f : check_functions
  if cc.has_function(f, prefix: have_prefix, args: cc_defs)
    cdata.set('HAVE_' + f.to_upper(),
              1,
              description: 'function ' + f)
  endif
endforeach

if cc.has_function('res_init', prefix: '''
  #include <netinet/in.h>
  #include <resolv.h>
''', args: cc_defs)
  cdata.set('HAVE_DECL_RES_INIT', 1)
endif

foreach type : check_types
  if cc.has_type(type, prefix: have_prefix, args: cc_defs)
    name = 'HAVE_' + type.to_upper().underscorify()
    cdata.set(name, 1, description: type)
  endif
endforeach

src_getopt = []
if not cdata.has('HAVE_GETOPT_H') or not cc.has_function('getopt_long', prefix: have_prefix, args: cc_defs)
  src_getopt = ['getopt.c', 'getopt1.c']
  src_lib_common += src_getopt
endif

if not opt_miniupnpc.disabled()
  dep_miniupnpc = dependency('miniupnpc', required: false, static: static)
  if not dep_miniupnpc.found()
    # No pkg-config files on MinGW
    dep_miniupnpc = cc.find_library('miniupnpc', required: opt_miniupnpc, static: static)
  endif
  if dep_miniupnpc.found()
    src_tincd += 'upnp.c'
    deps_tincd += [
      dependency('threads', static: static),
      dep_miniupnpc,
    ]
    if static
      cc_flags_tincd += '-DMINIUPNP_STATICLIB'
    endif
    cdata.set('HAVE_MINIUPNPC', 1)
  endif
endif

if not opt_curses.disabled()
  # The meta-dependency covers more alternatives, but is only available in 0.54+
  curses_name = meson_version.version_compare('>=0.54') ? 'curses' : 'ncurses'
  dep_curses = dependency(curses_name, required: opt_curses, static: static)
  if dep_curses.found()
    cdata.set('HAVE_CURSES', 1)
    deps_tinc += dep_curses
    if static
      cc_flags_tinc += '-DNCURSES_STATIC'
    endif
  endif
endif

# Some distributions do not supply pkg-config files for readline
if opt_readline.auto() and os_name == 'windows'
  message('readline not available on Windows')
else
  dep_readline = dependency('readline', required: opt_readline, static: static)
  if not dep_readline.found()
    dep_readline = cc.find_library('readline', required: opt_readline, static: static)
  endif
  if not dep_readline.found()
    dep_readline = cc.find_library('libedit', required: opt_readline, static: static)
  endif
  if dep_readline.found() and \
     cc.has_header('readline/readline.h', dependencies: dep_readline) and \
     cc.has_header('readline/history.h', dependencies: dep_readline)
    cdata.set('HAVE_READLINE', 1)
    deps_tinc += dep_readline
  endif
endif

dep_zlib = dependency('zlib',
                      required: opt_zlib,
                      static: static,
                      fallback: ['zlib', 'zlib_dep'])
if dep_zlib.found()
  cdata.set('HAVE_ZLIB', 1)
  deps_tincd += dep_zlib
endif

if not opt_lzo.disabled()
  dep_lzo = dependency('lzo2', required: false, static: static)
  if not dep_lzo.found()
    dep_lzo = cc.find_library('lzo2', required: opt_lzo, static: static)
  endif
  if not dep_lzo.found()
    dep_lzo = dependency('lzo2',
                         required: false,
                         static: static,
                         fallback: ['lzo2', 'lzo2_dep'])
  endif
  if dep_lzo.found()
    if dep_lzo.type_name() == 'internal' or cc.has_header('lzo/lzo1x.h', dependencies: dep_lzo)
      cdata.set('LZO1X_H', '<lzo/lzo1x.h>')
    elif cc.has_header('lzo1x.h', dependencies: dep_lzo)
      cdata.set('LZO1X_H', '<lzo1x.h>')
    else
      msg = 'lzo1x.h not found'
      if opt_lzo.auto()
        warning(msg)
      else
        error(msg)
      endif
    endif
    if cdata.has('LZO1X_H')
      cdata.set('HAVE_LZO', 1)
      deps_tincd += dep_lzo
    endif
  endif
endif

dep_lz4 = dependency('liblz4',
                     required: opt_lz4,
                     static: static,
                     fallback: ['lz4', 'liblz4_dep'])
if dep_lz4.found()
  deps_tincd += dep_lz4
  cdata.set('HAVE_LZ4', 1)
endif

dep_vde = dependency('vdeplug', required: opt_vde, static: static)
dep_dl = cc.find_library('dl', required: opt_vde)
if dep_vde.found() and dep_dl.found()
  cdata.set('ENABLE_VDE', 1)
  src_tincd += 'vde_device.c'
  deps_tincd += [dep_dl, dep_vde]
endif

if opt_jumbograms
  cdata.set('ENABLE_JUMBOGRAMS', 1)
endif

subdir(opt_crypto)

if opt_crypto != 'nolegacy'
  src_lib_crypto += ['cipher.c', 'digest.c']
endif

subdir('include')

have_sandbox = cdata.has('HAVE_SANDBOX')
if not have_sandbox
  src_lib_common += 'sandbox.c'
endif

lib_crypto = static_library(
  'tinc_crypto',
  sources: src_lib_crypto,
  dependencies: dep_crypto,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

deps_lib_common = [deps_common, dep_crypto]
deps_tinc += deps_lib_common
deps_tincd += deps_lib_common

lib_common = static_library(
  'common',
  sources: src_lib_common,
  dependencies: deps_lib_common,
  link_with: [lib_ed25519, lib_chacha_poly, lib_crypto],
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

lib_tinc = static_library(
  'tinc',
  sources: src_tinc,
  dependencies: deps_tinc,
  link_with: lib_common,
  c_args: cc_flags_tinc,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

lib_tincd = static_library(
  'tincd',
  sources: src_tincd,
  dependencies: deps_tincd,
  link_with: lib_common,
  c_args: cc_flags_tincd,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

exe_tinc = executable(
  'tinc',
  sources: 'tincctl.c',
  dependencies: deps_tinc,
  link_with: lib_tinc,
  implicit_include_directories: false,
  include_directories: inc_conf,
  install: true,
  install_dir: dir_sbin,
)

exe_tincd = executable(
  'tincd',
  sources: 'tincd.c',
  dependencies: deps_tincd,
  link_with: lib_tincd,
  c_args: cc_flags_tincd,
  implicit_include_directories: false,
  include_directories: inc_conf,
  install: true,
  install_dir: dir_sbin,
)

exe_sptps_test = executable(
  'sptps_test',
  sources: [src_getopt, 'sptps_test.c'],
  dependencies: deps_lib_common,
  link_with: lib_common,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

exe_sptps_keypair = executable(
  'sptps_keypair',
  sources: [src_getopt, 'sptps_keypair.c'],
  dependencies: deps_lib_common,
  link_with: lib_common,
  implicit_include_directories: false,
  include_directories: inc_conf,
  build_by_default: false,
)

if os_name == 'linux'
  dep_rt = cc.find_library('rt')

  exe_sptps_speed = executable(
    'sptps_speed',
    sources: 'sptps_speed.c',
    dependencies: [deps_lib_common, dep_rt],
    link_with: lib_common,
    implicit_include_directories: false,
    include_directories: inc_conf,
    build_by_default: false,
  )

  benchmark('sptps_speed', exe_sptps_speed, timeout: 90)
endif

