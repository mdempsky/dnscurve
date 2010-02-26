import sys

try:
  import nacl
except ImportError:
  import slownacl as nacl
import netstring

def main():
  sk = netstring.read(sys.stdin)
  pk = netstring.read(sys.stdin)
  nonce = netstring.read(sys.stdin)
  packet = netstring.read(sys.stdin)

  sys.stdout.write(nacl.box_curve25519xsalsa20poly1305_open(packet, nonce, pk, sk))

if __name__ == '__main__':
  main()
