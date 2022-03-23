win_common_libs = ['ws2_32', 'iphlpapi', 'winpthread']

if opt_harden
  win_common_libs += 'ssp'
endif

foreach libname : win_common_libs
  deps_common += cc.find_library(libname)
endforeach

src_tincd += files('device.c')

cdata.set('HAVE_MINGW', 1)

