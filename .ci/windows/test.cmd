set builddir=%1
set data=%builddir%\test-data
set tinc=%builddir%\src\tinc
set tincd=%tinc%d

mkdir %data% || exit 1

echo can tinc run at all?
%tinc% --version || exit 1

echo try to initialize a node
%tinc% -c %data% -b init foo || exit 1

echo try to generate EC keys
%tinc% -c %data% -b generate-ed25519-keys || exit 1

echo can tincd run?
%tincd% --version || exit 1

echo bail out if we're missing support for the legacy protocol
%tinc% --version | findstr legacy_protocol || exit 0

echo try to generate RSA keys
%tinc% -c %data% -b generate-keys || exit 1
