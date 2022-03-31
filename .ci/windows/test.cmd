set builddir=%1

REM Windows jobs on GitHub CI sometimes show surprisingly poor performance
REM (building tinc with default flags can take from 3 to upwards of 20+
REM minutes, depending on which machine you happened to land on), so timeout
REM is set a bit higher here.

meson test -C %builddir% --timeout-multiplier 2 --verbose || exit 1
