# Dependencies

Before you can start compiling tinc from a fresh git clone, you have
to install the very latest versions of the following packages:

- `meson`
- `ninja`
- `pkgconf` or `pkg-config`
- `GCC` or `Clang` (any version with C11 support, although older versions might work)
- `OpenSSL`\* (1.1.0+) or `LibreSSL` or `libgcrypt` (not needed if legacy protocol is disabled)

Plus a few optional dependencies. Support for them will be enabled if they're present:

- `ncurses` or `PDCurses`
- `readline`
- `zlib`\*
- `LZO`\*
- `LZ4`\*

If packages marked by `*` are not available, tinc will fall back to its own vendored copies.
This behavior can be disabled by setting the appropriate meson option to `disabled`.

To build `info` documentation you'll also need these packages:

- `texinfo` or `makeinfo`

You might also need some additional command-line utilities to be able to run the integration test suite:

- `diffutils`
- `procps`
- `socat`
- `netcat`

Please consult your operating system's documentation for more details.

## Windows

You will need to install [msys2][msys2] to build tinc under Windows.

[msys2]: https://msys2.org/

By default, tinc produces a static Windows build, so you don't need to install anything
in order to _run_ the compiled binaries.

# Building

## Native

Have a look at the available configuration options in `meson_options.txt`, or run:

    $ meson configure

The project can be built as any other meson project:

    $ meson setup build -Dprefix=/usr/local -Dbuildtype=release

This creates a build directory (named `build`) with build type set to `release`
(which enables compiler optimizations) and path prefix set to `/usr/local`.

Pass any additional options in the same way. Typically, this is not needed: tinc will
autodetect available libraries and adjust its functionality accordingly.

If you'd like to reconfigure the project after running `setup`, you can either remove
the build directory and start anew, or use:

    $ meson configure build -Dlzo=disabled -Dlz4=enabled

You then need to build the project:

    $ ninja -C build

You might want to run the test suite to ensure tinc is working correctly:

    $ ninja -C build test

To install tinc to your system, run:

    # ninja -C build install

Please be aware that this is not the best method of installing software
because it will not be tracked by your operating system's package manager. You
should use packages provided by your operating system, or build your own
(this is a large and complicated topic which is out of the scope of this document).

To uninstall tinc, run:

    # ninja -C build uninstall

## Cross-compilation

### Linux to Linux

Cross-compilation is easy to do on Debian or its derivatives.
Set `$HOST` to your target architecture and install the cross-compilation toolchain and `-dev` versions of all libraries you'd like to link:

    $ HOST=armhf
    $ dpkg --add-architecture $HOST
    $ apt update
    $ apt install -y crossbuild-essential-$HOST zlib1g-dev:$HOST …

If you'd like to run tests on emulated hardware, install `qemu-user`:

    $ apt install -y qemu-user
    $ update-binfmts --enable

Set two environment variables: the C compiler, and pkg-config, and then proceed as usual:

    $ export CC=arm-linux-gnueabihf-gcc
    $ export PKG_CONFIG=arm-linux-gnueabihf-pkg-config
    $ meson setup build --cross-file /dev/null

or put the names into a [cross file][cross] and pass it to meson:

    $ cat >cross-armhf <<EOF
    [binaries]
    c = 'arm-linux-gnueabihf-gcc'
    pkgconfig = 'arm-linux-gnueabihf-pkg-config'
    EOF

    $ meson setup build --cross-file cross-armhf

[cross]: https://mesonbuild.com/Cross-compilation.html

### Linux to Windows

Install cross-compilation toolchain:

    $ apt install -y mingw-w64 mingw-w64-tools

tinc will use its own vendored libraries, so you don't need to install or build anything manually.

Prepare the [cross file][cross] to let meson know you're building binaries for a different opearting system.
Take a look at the [file](.ci/cross/windows/amd64) used by CI for an example, or refer to examples provided
by the meson project: [x86][mingw32], [x86_64][mingw64].

Then build as usual. Because Windows binaries are built with static linkage by default,
you might want to enable link-time optimization. It is much slower than building without LTO,
but produces binaries that are 80%+ smaller:

    $ meson setup build -Dbuildtype=release -Db_lto=true --cross-file cross-windows
    $ ninja -C build

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

    $ export ANDROID_NDK_ROOT=/tmp/ndk/android-ndk-r24
    $ export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
    $ meson setup android-aarch64 -Dcrypto=nolegacy --cross-file android
    $ ninja -C android-aarch64

### macOS to iOS

The same instructions should work for iOS.
Refer to this [cross file][ios] for an example.

[ios]: https://github.com/mesonbuild/meson/blob/master/cross/iphone.txt
