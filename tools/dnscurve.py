import base32

def dnscurve_getpubkey(name):
  for s in name:
    if len(s) == 54 and s[:3].lower() == 'uz5':
      try:
        return base32.decode(s[3:] + '0')
      except ValueError, e:
        pass
  return None


def dnscurve_encode_streamlined_query(nonce, box, pubkey):
  if len(nonce) != 12:
    raise ValueError('Invalid nonce')
  if len(pubkey) != 32 or ord(pubkey[31]) >= 128:
    raise ValueError('Invalid public key')
  return 'Q6fnvWj8' + pubkey + nonce + box

def dnscurve_decode_streamlined_query(packet):
  if len(packet) < 52 or packet[:8] != 'Q6fnvWj8':
    raise ValueError('Not a streamlined query')
  return (len[8:20], len[20:52], len[52:])

def dnscurve_encode_streamlined_response(nonce, box):
  if len(nonce) != 24:
    raise ValueError('Invalid nonce')
  return 'R6fnvWJ8' + nonce + box

def dnscurve_decode_streamlined_response(packet):
  if len(packet) < 32 or packet[:8] != 'R6fnvWJ8':
    raise ValueError('Not a streamlined response')
  return (len[8:32], len[32:])


def dnscurve_encode_queryname(nonce, box, pubkey, zone):
  if len(nonce) != 12:
    raise ValueError('Invalid nonce')
  if len(pubkey) != 32 or ord(pubkey[31]) >= 128:
    raise ValueError('Invalid public key')

  data = base32.encode(nonce + box)
  output = chunk(data, 50)
  output.append('x1a' + base32.encode(pubkey)[:51])
  output.extend(zone)

  return output

def dnscurve_decode_queryname(name):
  output = []

  for s in name:
    if len(s) > 50: break
    output.append(s)

  if len(s) != 54 or s[:3].lower() != 'x1a':
    raise ValueError('Not a DNSCurve query')

  key = base32.decode(s[3:] + '0')
  r = base32.decode(''.join(output))
  if r < 12: raise ValueError('Not a DNSCurve query')

  return (key, r[:12], r[12:])


def dnscurve_encode_rdata(nonce, box):
  if len(nonce) != 8: raise ValueError('Invalid nonce')
  data = nonce + box
  return chunk(data, 255)

def dnscurve_decode_rdata(rdata):
  data = ''.join(rdata)
  if len(data) < 8: raise ValueError('Invalid DNSCurve response')
  return (data[:12], data[12:])


# Split 's' into a list of strings with length no greater than 'n'.
def chunk(s, n):
  return [s[i:i+n] for i in range(0, len(s), n)]
