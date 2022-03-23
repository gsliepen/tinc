dep_systemd = dependency('systemd', required: opt_systemd)
if not dep_systemd.found()
  subdir_done()
endif

dir_systemd = get_option('systemd_dir')
if dir_systemd == ''
  if meson_version.version_compare('>=0.58')
    dir_systemd = dep_systemd.get_variable('systemdsystemunitdir', pkgconfig_define: ['prefix', prefix])
  else
    dir_systemd = dep_systemd.get_pkgconfig_variable('systemdsystemunitdir', define_variable: ['prefix', prefix])
  endif
endif

systemd_conf = configuration_data()
systemd_conf.set('sysconfdir', dir_sysconf)
systemd_conf.set('sbindir', dir_sbin)

configure_file(input: 'tinc.service.in',
               output: 'tinc.service',
               configuration: systemd_conf,
               install_dir: dir_systemd)

configure_file(input: 'tinc@.service.in',
               output: 'tinc@.service',
               configuration: systemd_conf,
               install_dir: dir_systemd)

