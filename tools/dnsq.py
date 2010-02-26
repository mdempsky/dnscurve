#!/usr/bin/env python

# usage: dnsq type name server [ pubkey [ zone ] ]
#
# dnsq.py sends a non-recursive DNS query to DNS server `server` for
# records of type `type` under the domain name `fqdn`.
#
# If `pubkey` is provided, it should be either a hex encoding of the
# server's DNSCurve public key or a domain name containing the
# DNSCurve public key.  Additionally, if specified, dnsq.py will
# encrypt its request using the server's public key and a randomly
# generated secret key.
#
# If `zone` is provided, it tells dnsq.py to use the TXT format for
# DNSCurve and to use the specified zone.

# Examples:
#
# Send a DNS query for "hello.x.dempsky.org" to 70.85.31.66:
#     $ python dnsq.py txt hello.x.dempsky.org 70.85.31.66
#
# Send the same query as a DNSCurve query in streamlined format:
#     $ python dnsq.py txt hello.x.dempsky.org 70.85.31.66 \
#         uz5p4utwsxu5p3r9xrw0ygddw2hxh7bkhd0vdwtbt92lf058ny1p79
#
# Send the same query as a DNSCurve query in TXT format:
#     $ python dnsq.py txt hello.x.dempsky.org 70.85.31.66 \
#         uz5p4utwsxu5p3r9xrw0ygddw2hxh7bkhd0vdwtbt92lf058ny1p79 dempsky.org

import sys
import socket
import getopt
import dns
import dnscurve
try:
    import nacl
except ImportError, e:
    import slownacl as nacl

type = sys.argv[1]
name = sys.argv[2]
server = sys.argv[3]
pubkey = len(sys.argv) >= 5 and sys.argv[4]
zone = len(sys.argv) >= 6 and dns.dns_domain_fromdot(sys.argv[5])

if pubkey:
    try:
        pubkey = pubkey.decode('hex')
        if len(pubkey) != 32:
            raise 'Invalid DNSCurve public key'
    except TypeError, e:
        pubkey = dnscurve.dnscurve_getpubkey(dns.dns_domain_fromdot(pubkey))
        if not pubkey:
            raise 'Invalid DNSCurve public key'

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((server, 53))

query = dns.dns_build_query(type, name)
if pubkey:
    mykey = open('/dev/urandom').read(32)
    mypubkey = nacl.smult_curve25519_base(mykey)
    key = nacl.box_curve25519xsalsa20poly1305_beforenm(pubkey, mykey)
    nonce1 = open('/dev/urandom').read(12)
    box = nacl.box_curve25519xsalsa20poly1305_afternm(query, nonce1 + 12 * '\0', key)
    if zone is not False:
        query = dnscurve.dnscurve_encode_txt_query(nonce1, box, mypubkey, zone)
    else:
        query = dnscurve.dnscurve_encode_streamlined_query(nonce1, box, mypubkey)
s.send(query)

response = s.recv(4096)
if pubkey:
    if zone is not False:
        nonce2, box = dnscurve.dnscurve_decode_txt_response(response)
    else:
        nonce2, box = dnscurve.dnscurve_decode_streamlined_response(response)
    if nonce2[:12] != nonce1:
        raise "Response nonce didn't match"
    response = nacl.box_curve25519xsalsa20poly1305_open_afternm(box, nonce2, key)

dns.dns_print(response)
