set crypto=%1
set builddir=%crypto%
set args=
set crossfile=.ci\cross\msvc\%HOST_ARCH%

if exist %crossfile% (
    set args=--cross-file %crossfile%
)

echo configure build directory
meson setup %builddir% -Dbuildtype=release -Dcrypto=%crypto% %args% || exit 1

echo build project
meson compile -C %builddir% || exit 1
