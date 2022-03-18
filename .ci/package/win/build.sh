#!/bin/bash

set -euxo pipefail

curl -o wintap.exe -L 'https://build.openvpn.net/downloads/releases/latest/tap-windows-latest-stable.exe'

makensis .ci/package/win/installer.nsi
