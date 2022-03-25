set crypto=%1
set builddir=%crypto%

echo configure build directory
meson setup %builddir% -Dbuildtype=release -Dcrypto=%crypto% || exit 1

echo build project
meson compile -C %builddir% || exit 1
