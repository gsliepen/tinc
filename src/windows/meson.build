check_headers += 'w32api.h'

win_common_libs = ['ws2_32', 'iphlpapi', 'threads']

if opt_harden and cc_name != 'msvc'
  win_common_libs += 'ssp'
endif

foreach libname : win_common_libs
  dep = dependency(libname, required: false)
  if not dep.found()
    dep = cc.find_library(libname)
  endif
  deps_common += dep
endforeach

src_lib_common += files('random.c')

src_tincd += files(
  'device.c',
  'event.c',
)

