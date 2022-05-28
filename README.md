# About tinc

Tinc is a peer-to-peer VPN daemon that supports VPNs with an arbitrary number of
nodes. Instead of configuring tunnels, you give tinc the location and public key
of a few nodes in the VPN. After making the initial connections to those nodes,
tinc will learn about all other nodes on the VPN, and will make connections
automatically. When direct connections are not possible, data will be forwarded
by intermediate nodes.

Tinc can operate in several routing modes. In the default mode, "router", every
node is associated with one or more IPv4 and/or IPv6 Subnets. The other two
modes, "switch" and "hub", let the tinc daemons work together to form a virtual
Ethernet network switch or hub.

## This is a pre-release

Please note that this is NOT a stable release. Until version 1.1.0 is released,
please use one of the 1.0.x versions if you need a stable version of tinc.

Although tinc 1.1 will be protocol compatible with tinc 1.0.x, the functionality
of the tinc program may still change, and the control socket protocol is not
fixed yet.

# Documentation

See [QUICKSTART.md](QUICKSTART.md) for a quick guide to get tinc up and running.
Read the [manual](https://www.tinc-vpn.org/documentation-1.1/) for more detailed
information.

# Getting tinc

## From your distribution

Many operating system distributions have packaged tinc. Check your package
manager first.

## Nightly builds

You can download pre-built binary packages for multiple Linux distributions and
Windows here:

- [development version](https://github.com/gsliepen/tinc/releases/tag/latest)
- [latest release](https://github.com/gsliepen/tinc/releases/latest)

Note that these packages have not been heavily tested and are not officially
supported by the project. Use them at your own risk. You are advised to use tinc
shipped by your distribution, or build from source.

## Build it from source

See the file [INSTALL.md](INSTALL.md) for instructions of how to build and
install tinc from source.

# Copyright

tinc is Copyright © 1998-2022 Ivo Timmermans, Guus Sliepen <guus@tinc-vpn.org>,
and others.

For a complete list of authors see the [AUTHORS](AUTHORS) file.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version. See the file COPYING for more details.
