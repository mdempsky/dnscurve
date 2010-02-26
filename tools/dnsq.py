#!/usr/bin/env python

import sys
import socket
import getopt
import dns

type, name, server = sys.argv[1:]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((server, 53))

query = dns.dns_build_query(type, name)
s.send(query)
response = s.recv(4096)
dns.dns_print(response)
