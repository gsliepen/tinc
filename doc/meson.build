man_pages = [
  'tinc-gui.8.in',
  'tinc.8.in',
  'tinc.conf.5.in',
  'tincd.8.in',
]

info_pages = [
  'tinc.texi',
]

info_includes = [
  'tincinclude.texi.in',
]

man_conf = configuration_data()
man_conf.set_quoted('PACKAGE', meson.project_name())
man_conf.set_quoted('VERSION', meson.project_version())
man_conf.set_quoted('localstatedir', dir_local_state)
man_conf.set_quoted('runstatedir', dir_run_state)
man_conf.set_quoted('sysconfdir', dir_sysconf)

foreach man_src : man_pages
  man = configure_file(
    input: man_src,
    output: '@BASENAME@',
    configuration: man_conf,
  )
  install_man(man)
endforeach

prog_makeinfo = find_program('makeinfo', required: opt_docs)
if not prog_makeinfo.found()
  subdir_done()
endif

foreach inc : info_includes
  configure_file(
    input: inc,
    output: '@BASENAME@',
    configuration: man_conf,
  )
endforeach

info_cmd = [
  prog_makeinfo,
  '-P', '@BUILD_ROOT@/doc',
  '@INPUT@',
  '--output', '@OUTPUT@',
]

foreach page : info_pages
  custom_target(
    'info-page-' + page,
    input: page,
    output: '@BASENAME@.info',
    command: info_cmd,
    install: true,
    install_dir: dir_info,
  )
endforeach

