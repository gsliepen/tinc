# Dependencies

## Required

Before you can start compiling tinc from a fresh git clone, you have to install
the very latest versions of the following packages:

- `meson` or `muon` (read below)
- `ninja` or `samurai`
- `pkgconf` or `pkg-config`
- `GCC` or `Clang` (any version with C11 support, although older versions might
  work)
- `OpenSSL`\* (1.1.0+) or `LibreSSL` or `libgcrypt` (not needed if legacy
  protocol is disabled)

### No Python?

If you're on a constrained system that doesn't have (or cannot run) Python, you
can try building tinc with [muon][muon], which is a pure C reimplementation of
the same idea. Please note that `meson` is considered to be the main way of
building tinc, and `muon` is supported on a best-effort basis.

[muon]: https://git.sr.ht/~lattis/muon

## Optional

Plus a few optional dependencies. Support for them will be enabled if they're
present:

- `ncurses` or `PDCurses`
- `readline`
- `zlib`\*
- `LZO`\*
- `LZ4`\*

If packages marked by `*` are not available, tinc will fall back to its own
vendored copies. This behavior can be disabled by setting the appropriate meson
option to `disabled`.

To build `info` documentation you'll also need these packages:

- `texinfo` or `makeinfo`

You might also need some additional command-line utilities to be able to run the
integration test suite:

- `diffutils`
- `procps`
- `socat`
- `netcat`


## Linux

Depending on the distribution, one of the following commands can be used to install all dependencies:
- Arch Linux: `sudo pacman --needed --sync base-devel meson ninja pkg-config openssl ncurses readline zlib lzo lz4 texinfo diffutils procps socat openbsd-netcat`
- Debian: `sudo apt install meson ninja-build pkg-config build-essential libssl-dev libncurses-dev libreadline-dev zlib1g-dev liblzo2-dev liblz4-dev texinfo diffutils procps socat netcat-openbsd`
- Alpine Linux: `doas apk add meson ninja pkgconf build-base linux-headers openssl-dev ncurses-dev readline-dev zlib-dev lzo-dev lz4-dev texinfo diffutils procps-ng socat netcat-openbsd`
- Fedora: `sudo dnf install meson ninja-build pkgconf-pkg-config @development-tools openssl-devel ncurses-devel readline-devel zlib-devel lzo-devel lz4-devel texinfo diffutils procps-ng socat netcat`

## Windows

You can build tinc using either the native [Windows SDK][sdk-ms] (which comes
with Visual Studio), or with the Unix-like [msys2 environment][sdk-msys2].
Install either one of them, plus the latest version of [meson][meson-release].

If you prefer the native SDK, you might want to work on tinc (or build it) under
Visual Studio. To do so, follow [these instructions][meson-vs].

By default, tinc produces a static Windows build, so you don't need to install
anything in order to _run_ the compiled binaries.

[sdk-ms]: https://visualstudio.com/
[sdk-msys2]: https://msys2.org/
[meson-release]: https://github.com/mesonbuild/meson/releases
[meson-vs]: https://mesonbuild.com/Using-with-Visual-Studio.html

# Building from source

## Native

### Setup

Tinc's functionality can vary greatly depending on how you configure it. Have a
look at the available options in [`meson_options.txt`](meson_options.txt), or
run:

```sh
meson configure
```

First you need to create a build directory. If you want the default experience,
run:

```sh
meson setup builddir
```

or with configuration options (your shell can probably autocomplete them on
`Tab`, try it):

```sh
meson setup builddir -Dprefix=/usr/local -Dbuildtype=release
```

(For autotools users: this is a rough equivalent of
`autoreconf -fsi && ./configure --prefix=/usr/local --with-foobar`).

This creates a build directory (named `builddir`) with build type set to
`release` (which enables compiler optimizations) and path prefix set to
`/usr/local`.

Pass any additional options in the same way. Typically, this is not needed: tinc
will autodetect available libraries and adjust its functionality accordingly.

If you'd like to reconfigure the project after running `setup`, you can either
remove the build directory and start anew, or use:

```sh
meson configure builddir -Dlzo=disabled -Dlz4=enabled
```

### Compile

You then need to build the project:

```sh
meson compile -C builddir
```

(For autotools users: this is an equivalent of `make -j$(nproc)`).

### Test

You might want to run the test suite to ensure tinc is working correctly:

```sh
meson test -C builddir
```

(For autotools users: this is an equivalent of `make -j$(nproc) test`).

### Install

To install tinc to your system, run:

```sh
meson install -C builddir
```

(For autotools users: this is an equivalent of `make install`).

Please be aware that this is not the best method of installing software because
it will not be tracked by your operating system's package manager. You should
use packages provided by your operating system, or build your own (this is a
large and complicated topic which is out of the scope of this document).

### Uninstall

To uninstall tinc, run:

```sh
ninja -C builddir uninstall
```

(For autotools users: this is an equivalent of `make uninstall`).

## Cross-compilation

### Linux to Linux

Cross-compilation is easy to do on Debian or its derivatives. Set `$HOST` to
your target architecture and install the cross-compilation toolchain and `-dev`
versions of all libraries you'd like to link:

```sh
HOST=armhf
dpkg --add-architecture $HOST
apt update
apt install -y crossbuild-essential-$HOST zlib1g-dev:$HOST …
```

If you'd like to run tests on emulated hardware, install `qemu-user`:

```sh
apt install -y qemu-user
update-binfmts --enable
```

Set two environment variables: the C compiler, and pkg-config, and then proceed
as usual:

```sh
export CC=arm-linux-gnueabihf-gcc
export PKG_CONFIG=arm-linux-gnueabihf-pkg-config
meson setup build --cross-file /dev/null
```

Or put the names into a [cross file][cross] and pass it to meson:

```sh
cat >cross-armhf <<EOF
[binaries]
c = 'arm-linux-gnueabihf-gcc'
pkgconfig = 'arm-linux-gnueabihf-pkg-config'
EOF

meson setup build --cross-file cross-armhf
```

[cross]: https://mesonbuild.com/Cross-compilation.html

### Linux to Windows

Install cross-compilation toolchain:

```sh
apt install -y mingw-w64 mingw-w64-tools
```

tinc will use its own vendored libraries, so you don't need to install or build
anything manually.

Prepare the [cross file][cross] to let meson know you're building binaries for a
different operating system. Take a look at the [file](.ci/cross/windows/amd64)
used by CI for an example, or refer to examples provided by the meson project:
[x86][mingw32],[x86_64][mingw64].

Then build as usual. Because Windows binaries are built with static linkage by
default, you might want to enable link-time optimization. It is much slower than
building without LTO, but produces binaries that are 80%+ smaller:

```sh
meson setup build -Dbuildtype=release -Db_lto=true --cross-file cross-windows
ninja -C build
```

[mingw64]: https://github.com/mesonbuild/meson/blob/master/cross/linux-mingw-w64-64bit.txt
[mingw32]: https://github.com/mesonbuild/meson/blob/master/cross/linux-mingw-w64-32bit.txt

### Linux to Android

First you need to install [Android NDK][ndk].

[ndk]: https://developer.android.com/studio/projects/install-ndk

Prepare a [cross file][cross]. Here's a working example for reference:

```ini
[host_machine]
system     = 'android'
cpu_family = 'arm'
cpu        = 'aarch64'
endian     = 'little'

[binaries]
c = 'aarch64-linux-android24-clang'
```

Then build as usual:

```sh
export ANDROID_NDK_ROOT=/tmp/ndk/android-ndk-r24
export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
meson setup android-aarch64 -Dcrypto=nolegacy --cross-file android
ninja -C android-aarch64
```

### macOS to iOS

The same instructions should work for iOS. Refer to this [cross file][ios] for
an example.

[ios]: https://github.com/mesonbuild/meson/blob/master/cross/iphone.txt
