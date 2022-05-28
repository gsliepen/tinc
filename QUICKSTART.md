# Creating a new VPN

If you are just starting to create a VPN, first consider what IP addresses you
want to use on the VPN. There are several blocks of IP addresses reserved for
[private networks](https://en.wikipedia.org/wiki/Private_network):

- 192.168.0.0/16
- 172.16.0.0/12
- 10.0.0.0/8
- fd00::/8

Make sure the [IP range](https://en.wikipedia.org/wiki/CIDR) you are choosing is
large enough for all the nodes you want to add to the VPN, and also consider
that some of these private address ranges might also be used on local area
networks, so check in advance that you won't conflict with any range that is
already in use by any of the participants. When in doubt, just pick one and try
it out. For this quickstart guide, we will use 172.16.0.0/16 as the range of the
VPN.

Also think of a name for your whole VPN. This will be used as the "netname"
parameter for tinc, and on Linux this will then also automatically be used as
the name for the virtual network interface. We will use "myvpn" as the name in
the examples below.

# Create your first node

Think of a name for your first node. We will call it "first" in the examples
below. The name must be unique for each node in the same VPN, and may only
contain letters, numbers and underscores. Apart from that you can choose
whatever you want. Now we can create the first node:

```sh
sudo tinc -n myvpn init first
```

This creates the initial configuration for the node, but has not started tinc
yet. Before we do that, two things have to be done first. We have to tell tinc
which part of the IP range of the VPN belongs to *this* particular node. We will
use 172.168.1.0/24 for this example. We then have to give this command:

```sh
sudo tinc -n myvpn add Subnet 172.168.1.0/24
```

However, tinc itself will not actually configure the virtual network interface
for you. You have to create a script named `tinc-up` that does this. To do this,
run the command:

```sh
sudo tinc -n myvpn edit tinc-up
```

This should start an editor. When you ran the `init` command, a dummy script was
already created. Edit it to make sure it looks like this:

```sh
#!/bin/sh
ifconfig $INTERFACE 172.168.1.1/16
```

Note that the literal text `$INTERFACE` should be in the script, tinc will make
sure that environment variable is set correctly when the script is run. The
address should be that of the node itself, but the netmask or prefix length (the
`/16` in this case) you provide must be that of the *whole* VPN. This tells the
kernel that everything for the VPN's IP range should go to tinc's virtual
network interface, from then on tinc will handle it and route it to the right
node based on the `Subnet`s that you configured.

To start tinc run:

```sh
sudo tinc -n myvpn start
```

This will start running tinc in the background. You can also run it in the
foreground with debugging enabled using this command:

```sh
sudo tinc -n myvpn start -d5 -D
```

This might be helpful in the beginning to debug any issues you have setting up
the VPN.

# Create your second node

There are two ways to add new nodes to the VPN.

## Using import/export of host config files

One way to do it is to create a second node just like you created the first
node. Just make sure it has a different name (let's call it "second"), and that
it gets a different IP range for itself (let's use 172.168.2.0/24). So on the
second node run:

```sh
sudo tinc -n myvpn init second
sudo tinc -n myvpn add Subnet 172.168.2.0/24
sudo tinc -n myvpn edit tinc-up
```

And make sure the second node's tinc up contains:

```sh
#!/bin/sh
ifconfig $INTERFACE 172.168.2.1/16
```

And `start` the second node. After you have done that, you have to make sure
that the two nodes can find each other. To do this, at least one node should
have a public IP address. Let's assume the first node has public IP address
93.184.216.34. You would then give this command on the first node:

```sh
sudo tinc -n myvpn add Address 93.184.216.34
```

Note that if you have a public domain name, you can also use that domain name
instead of a numeric IP address. Now run the following on the first node:

```sh
sudo tinc -n myvpn export
```

This outputs a small amount of text that contains the node's public keys and the
public address. On the second node, run this:

```sh
sudo tinc -n myvpn import
```

And copy&paste the output from the first node, then press ctrl-D on a new line.
If done correctly it should tell you that it has imported the host configuration
file. Now you have to do the same but in the other direction: use the `export`
command on the second node, and then use `import` on the first node. Now that
both nodes know each other, they should be able to connect. This should happen
automatically after a while.

Note that instead of copy&pasting the text manually, you could also redirect it
to a text file, send it via email, pipe it through an SSH connection, or use any
other way to exchange the host config files. For more information, see the
[manual](https://www.tinc-vpn.org/documentation-1.1/How-to-configure.html).

## Using invitations

Another way to add more nodes is to have an existing node generate an
[invitation](https://www.tinc-vpn.org/documentation-1.1/Invitations.html) for
another node. A prerequisite is that the node generating the invitation should
have a public IP address to the invitee will be able to connect to it. Again,
let's assume the first node has public IP address 93.184.216.34:

```sh
sudo tinc -n myvpn add Address 93.184.216.34
```

Then on the first node, generate in invitation for the second node:

```sh
sudo tinc -n myvpn invite second
```

This should generate one line of text that looks like an URL, like for example:

```
93.184.216.34:655/R4BU9VMzdY4S_EIuAhW1-B0XV50HqooyEv6EUfl4k6Z9_zrq
```

On the second node, don't using `init` to create the initial configuration.
Instead, run the following command:

```sh
sudo tinc -n myvpn join 93.184.216.34:655/R4BU9VMzdY4S_EIuAhW1-B0XV50HqooyEv6EUfl4k6Z9_zrq
```

It will then initialize itself and make a connection to the first node and
exchange configuration files automatically. You still have to add the `Subnet`
and edit `tinc-up` afterwards on the second node (as described in the section
above), and use the `start` command to start tinc.

Invitations are easier to use, and relatively secure. Once used, the invitation
is no longer valid. However, be aware that anyone holding an unused invitation
can use it to join a VPN, so make sure you do not make invitation URLs public.

# Checking that things are working

After you have set up two nodes, you should be able to ping `172.16.1.1`. If it
doesn't work, there can be multiple reasons. Make sure you don't have any
firewall rules blocking tinc's port, and that at least one node has a public IP
address that is accepting incoming connections. You can further investigate by
asking tinc the status of a given node. So for example, on the first node, you
can run:

```sh
sudo tinc -n myvpn info second
```

You can also dump a list of connections:

```sh
sudo tinc -n myvpn dump connections
```

Or `dump nodes` to get a list of known nodes, `dump subnets` to see all subnets.
If you ran tinc in the background, you can get still get log output like so:

```sh
sudo tinc -n myvpn log 5
```

Finally, if the problem is not with tinc, using `tcpdump` to look at the traffic
on your real and virtual interfaces might help determine what the problem is.
