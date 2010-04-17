#!/usr/bin/python

import string
import socket

REQ_STOP = 0
REQ_RELOAD = 1
REQ_RESTART = 2
REQ_DUMP_NODES = 3
REQ_DUMP_EDGES = 4
REQ_DUMP_SUBNETS = 5
REQ_DUMP_CONNECTIONS = 6
REQ_DUMP_GRAPH = 7
REQ_PURGE = 8
REQ_SET_DEBUG = 9
REQ_RETRY = 10
REQ_CONNECT = 11
REQ_DISCONNECT = 12

ID = 0
ACK = 4
CONTROL = 18

class Node:
	def __init__(self):
		print('New node')

	def __exit__(self):
		print('Deleting node ' + self.name)

	def parse(self, args):
		self.name = args[0]
		self.address = args[2]
		if args[3] != 'port':
			args.insert(3, 'port')
			args.insert(4, '')
		self.port = args[4]
		self.cipher = int(args[6])
		self.digest = int(args[8])
		self.maclength = int(args[10])
		self.compression = int(args[12])
		self.options = int(args[14], 0x10)
		self.status = int(args[16], 0x10)
		self.nexthop = args[18]
		self.via = args[20]
		self.distance = int(args[22])
		self.pmtu = int(args[24])
		self.minmtu = int(args[26])
		self.maxmtu = int(args[28][:-1])

		self.subnets = {}

class Edge:
	def parse(self, args):
		self.fr = args[0]
		self.to = args[2]
		self.address = args[4]
		self.port = args[6]
		self.options = int(args[8], 16)
		self.weight = int(args[10])

class Subnet:
	def parse(self, args):
		if args[0].find('#') >= 0:
			(address, self.weight) = args[0].split('#', 1)
		else:
			self.weight = 10
			address = args[0]

		if address.find('/') >= 0:
			(self.address, self.prefixlen) = address.split('/', 1)
		else:
			self.address = address
			self.prefixlen = '48'

		self.owner = args[2]	

class Connection:
	def parse(self, args):
		self.name = args[0]
		self.address = args[2]
		if args[3] != 'port':
			args.insert(3, 'port')
			args.insert(4, '')
		self.port = args[4]
		self.options = int(args[6], 0x10)
		self.socket = int(args[8])
		self.status = int(args[10], 0x10)
		self.weight = 123

class VPN:
	confdir = '/etc/tinc'
	cookiedir = '/var/run/'

	def connect(self):
		f = open(self.cookiefile)
		cookie = string.split(f.readline())
		f.close()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('127.0.0.1', int(cookie[1])))
		self.sf = s.makefile()
		s.close()
		hello = string.split(self.sf.readline())
		self.name = hello[1]
		self.sf.write('0 ^' + cookie[0] + ' 17\r\n')
		self.sf.flush()
		resp = string.split(self.sf.readline())
		self.port = cookie[1]
		self.nodes = {}
		self.edges = {}
		self.subnets = {}
		self.connections = {}
		self.refresh()

	def refresh(self):
		self.sf.write('18 3\r\n18 4\r\n18 5\r\n18 6\r\n')
		self.sf.flush()

		for node in self.nodes.values():
			node.visited = False
		for edge in self.edges.values():
			edge.visited = False
		for subnet in self.subnets.values():
			subnet.visited = False
		for connections in self.connections.values():
			connections.visited = False

		while True:
			resp = string.split(self.sf.readline())
			if len(resp) < 2:
				break
			if resp[0] != '18':
				break
			if resp[1] == '3':
				if len(resp) < 3:
					continue
				node = self.nodes.get(resp[2]) or Node()
				node.parse(resp[2:])
				node.visited = True
				self.nodes[resp[2]] = node
			elif resp[1] == '4':
				if len(resp) < 5:
					continue
				edge = self.nodes.get((resp[2], resp[4])) or Edge()
				edge.parse(resp[2:])
				edge.visited = True
				self.edges[(resp[2], resp[4])] = edge
			elif resp[1] == '5':
				if len(resp) < 5:
					continue
				subnet = self.subnets.get((resp[2], resp[4])) or Subnet()
				subnet.parse(resp[2:])
				subnet.visited = True
				self.subnets[(resp[2], resp[4])] = subnet
				self.nodes[subnet.owner].subnets[resp[2]] = subnet
			elif resp[1] == '6':
				if len(resp) < 5:
					break
				connection = self.connections.get((resp[2], resp[4])) or Connection()
				connection.parse(resp[2:])
				connection.visited = True
				self.connections[(resp[2], resp[4])] = connection
			else:
				break

		for key, subnet in self.subnets.items():
			if not subnet.visited:
				del self.subnets[key]

		for key, edge in self.edges.items():
			if not edge.visited:
				del self.edges[key]

		for key, node in self.nodes.items():
			if not node.visited:
				del self.nodes[key]
			else:
				for key, subnet in node.subnets.items():
					if not subnet.visited:
						del node.subnets[key]

		for key, connection in self.connections.items():
			if not connection.visited:
				del self.connections[key]

	def close(self):
		self.sf.close()

	def disconnect(self, name):
		self.sf.write('18 12 ' + name + '\r\n')
		self.sf.flush()
		resp = string.split(self.sf.readline())

	def debug(self, level = -1):
		self.sf.write('18 9 ' + str(level) + '\r\n')
		self.sf.flush()
		resp = string.split(self.sf.readline())
		return int(resp[2])

	def __init__(self, netname = None, controlcookie = None):
		self.tincconf = VPN.confdir + '/'

		if netname:
			self.netname = netname
			self.tincconf += netname + '/'

		self.tincconf += 'tinc.conf'

		if controlcookie is not None:
			self.cookiefile = controlcookie
		else:
			self.cookiefile = VPN.cookiedir + 'tinc.'
			if netname:
				self.cookiefile += netname + '.'
			self.cookiefile += 'cookie'
