#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "crypto_box_curve25519xsalsa20poly1305.h"

#include "dns.h"
#include "base32.h"

extern uint8_t global_secret_key[32];

unsigned
dns_packet_getname(uint8_t *name, unsigned namemax,
                   const uint8_t *buf, unsigned len, unsigned pos) {
  unsigned int loop = 0;
  unsigned int state = 0;
  unsigned int firstcompress = 0;
  unsigned int where;
  uint8_t ch;
  unsigned int namelen = 0;

  for (;;) {
    if (pos >= len) goto PROTO;
    ch = buf[pos++];
    if (++loop >= 4096) goto PROTO;

    if (state) {
      if (namelen + 1 > namemax) goto PROTO;
      name[namelen++] = ch;
      --state;
    } else {
      while (ch >= 192) {
        where = ch; where -= 192; where <<= 8;
        if (pos >= len) goto PROTO;
        ch = buf[pos++];
        if (!firstcompress) firstcompress = pos;
        pos = where + ch;
        if (pos >= len) goto PROTO;
        ch = buf[pos++];
        if (++loop >= 4096) goto PROTO;
      }
      if (ch >= 64) goto PROTO;
      if (namelen + 1 > namemax) goto PROTO;
      name[namelen++] = ch;
      if (!ch) break;
      state = ch;
    }
  }

  if (firstcompress) return firstcompress;
  return pos;

 PROTO:
  errno = EPROTO;
  return 0;
}

int
dns_curve_name_parse(uint8_t *box, unsigned *boxlen,
                     uint8_t *publickey, unsigned *zone,
                     const uint8_t *name) {
  uint8_t encoded_box[4096];
  unsigned encoded_boxlen = 0;
  unsigned i = 0;

  errno = EPROTO;

  // Concatenate the base32 encoded components which make up the nonce and box
  for (;;) {
    const uint8_t component_len = name[i];
    if (component_len == 54) {
      break;
    } else if (component_len > 50) {
      return 0;
    } else if (component_len == 0) {
      return 0;
    }

    if (encoded_boxlen + component_len > sizeof(encoded_box))
      goto NAMETOOLONG;
    memcpy(encoded_box + encoded_boxlen, name + i + 1, component_len);
    encoded_boxlen += component_len;
    i += component_len + 1;
  }

  // Base32 decode the box
  if (!base32_decode(box, boxlen, encoded_box, encoded_boxlen, 0))
    return 0;

  // Next is the public key
  if (!(name[i] == 54 &&
        (name[i+1] & ~0x20) == 'X' &&
        name[i+2] == '1' &&
        (name[i+3] & ~0x20) == 'A'))
    return 0;

  unsigned publickeylen = 32;
  if (!base32_decode(publickey, &publickeylen, name + i + 4, 51, 1))
    return 0;
  if (publickeylen != 32)
    return 0;

  i += 54 + 1;
  *zone = i;

  return 1;

 NAMETOOLONG:
  errno = ENAMETOOLONG;
  return 0;
}

// -----------------------------------------------------------------------------
// Try to parse a packet as a DNS curve request
//
// plaintext: (output) a 4096 byte buffer which receives the enclosed packet
// plaintextlen: (output) on success, the length of the data in @plaintext
// public_key: (output) the client's public key (32-bytes)
// nonce: (output) the client's nonce (12-bytes)
// qname: (output) set to point within @buffer to the start of the query name
// qnamelen: (output) set to contain the number of bytes of query name
// buffer: the packet contents
// n: number of bytes in @buffer
// returns: 1 on success if TXT format, 2 on success if streamlined format,
// 0 if this doesn't appear to be a DNS curve packet and -1 if the DNS
// curve packet is invalid
// -----------------------------------------------------------------------------
int
dns_curve_request_parse(uint8_t *plaintext, unsigned *plaintextlen,
                        uint8_t *public_key, uint8_t *nonce,
                        const uint8_t **qname, unsigned *qnamelen,
                        const uint8_t *buffer, unsigned n) {
  uint8_t fullnonce[24];
  uint8_t nonce_and_box[4096];
  unsigned nonce_and_box_len = sizeof(nonce_and_box);

  // A streamlined formatted DNSCurve packet will be at least 68
  // bytes, while TXT formatted packets will be even longer.
  if (n < 68)
    return 0;

  // Check for a streamlined packet.
  if (!memcmp(buffer, "Q6fnvWj8", 8)) {
    memcpy(public_key, buffer + 8, 32);
    memcpy(fullnonce, buffer + 40, 12);
    memset(fullnonce + 12, 0, 12);
    memset(nonce_and_box, 0, 16);
    memcpy(nonce_and_box + 16, buffer + 52, n - 52);
    nonce_and_box_len = n - 36;

    if (-1 == crypto_box_curve25519xsalsa20poly1305_open
        (nonce_and_box, nonce_and_box, nonce_and_box_len, fullnonce,
         public_key, global_secret_key))
      return 0; // Not a valid DNSCurve packet, but might be a valid DNS query.

    memcpy(nonce, fullnonce, 12);
    memcpy(plaintext, nonce_and_box + 32, nonce_and_box_len - 32);
    *plaintextlen = nonce_and_box_len - 32;
    return 1;
  }

  // First two bytes are the client selected transaction id
  uint16_t transid;
  memcpy(&transid, buffer, 2);

  // query, opcode 0, not authoritative, not truncated;
  // recursion may or may not be desired
  if ((buffer[2] & ~1) != 0)
    return 0;

  if (memcmp(buffer + 3, "\x00" // recursion not available, no Z bits, RCODE 0
                         "\x00\x01"  // exactly one question
                         "\x00\x00"  // no answer records
                         "\x00\x00"  // no authority records
                         "\x00\x00", // no additional records
                         9))
    return 0;

  uint8_t queryname[4096];
  unsigned pos = 12;

  *qname = buffer + 12;
  pos = dns_packet_getname(queryname, sizeof(queryname), buffer, n, pos);
  if (!pos)
    return 0;
  *qnamelen = pos - 12;

  if (n - pos != 4)
    return 0;

  if (memcmp(&buffer[pos], "\x00\x10"      // query type TXT
                           "\x00\x01", 4)) // internet class
    return 0;

  unsigned server_zone;

  /* skip the first 4 bytes so the box is already in place */
  nonce_and_box_len -= 4;
  if (!dns_curve_name_parse(nonce_and_box + 4, &nonce_and_box_len,
                            public_key, &server_zone, queryname))
    return 0;
  nonce_and_box_len += 4;

  if (nonce_and_box_len < 32)
    return 0;
  if (*plaintextlen < nonce_and_box_len - 32)
    return 0;

  memcpy(fullnonce, nonce_and_box + 4, 12);
  memset(fullnonce + 12, 0, 12);
  memset(nonce_and_box, 0, 16);

  if (-1 == crypto_box_curve25519xsalsa20poly1305_open
      (nonce_and_box, nonce_and_box, nonce_and_box_len, fullnonce,
       public_key, global_secret_key))
    return 0;

  memcpy(nonce, fullnonce, 12);
  memcpy(plaintext, nonce_and_box + 32, nonce_and_box_len - 32);
  *plaintextlen = nonce_and_box_len - 32;

  return buffer[2] ? 3 : 2;
}

int
dns_curve_request_build(uint8_t *output, unsigned *ooutlen,
                        const uint8_t *box, unsigned boxlen,
                        const uint8_t *public_key,
                        const uint8_t *zone) {
  uint8_t encoded[4096];
  unsigned encodedlen = sizeof(encoded);
  unsigned i = 0, j = 0;
  const unsigned outlen = *ooutlen;

  if (i + 10 > outlen)
    goto TOOBIG;

  memcpy(output + i, "\x00" // query, opcode 0, not authoritative, not
                            // truncated, recursion not desired
                     "\x00" // recursion not available, no Z bits, RCODE 0
                     "\x00\x01"  // exactly one question
                     "\x00\x00"  // no answer records
                     "\x00\x00"  // no authority records
                     "\x00\x00", // no additional records
                     10);
  i += 10;

  if (!base32_encode(encoded, &encodedlen, box, boxlen))
    return 0;

  while (encodedlen) {
    unsigned component_length = encodedlen;
    if (component_length > 50)
      component_length = 50;

    if (i >= outlen)
      goto TOOBIG;
    output[i++] = component_length;
    if (i + component_length >= outlen)
      goto TOOBIG;
    memcpy(output + i, encoded + j, component_length);
    encodedlen -= component_length;
    j += component_length;
    i += component_length;
  }

  encodedlen = sizeof(encoded);
  if (!base32_encode(encoded, &encodedlen, public_key, 32))
    return 0;
  if (i + 55 >= outlen)
    goto TOOBIG;

  memcpy(output + i, "\x36x1a", 4);
  i += 4;
  memcpy(output + i, encoded, 51);
  i += 51;

  j = 0;
  while (zone[j]) {
    const unsigned component_length = zone[j++];
    if (i >= outlen)
      goto TOOBIG;
    output[i++] = component_length;
    if (i + component_length >= outlen)
      goto TOOBIG;
    memcpy(output + i, zone + j, component_length);
    i += component_length;
    j += component_length;
  }
  if (i >= outlen)
    goto TOOBIG;
  output[i++] = 0;

  if (i + 4 > outlen)
    goto TOOBIG;

  memcpy(output + i, "\x00\x10"      // query type TXT
                     "\x00\x01", 4); // internet class
  i += 4;

  *ooutlen = i;

  return 1;

 TOOBIG:
  errno = E2BIG;
  return 0;
}
