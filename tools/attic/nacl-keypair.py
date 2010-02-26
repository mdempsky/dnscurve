import sys

try:
  import nacl
except ImportError:
  import slownacl as nacl
import netstring

def main():
  (pk, sk) = nacl.box_curve25519xsalsa20poly1305_keypair()
  netstring.write(sys.stdout, sk)
  netstring.write(sys.stdout, pk)

if __name__ == '__main__':
  main()
