/* $Id: pad.c,v 1.6 1999/07/02 14:23:18 dm Exp $ */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/*
 * pre_encrypt turns a message into a bigint suitable for public-key
 * encryption.  On input, nbits is the number of bits the resulting
 * bigint should contain, while msg is the message.  Msg consists of
 * an integral number of bytes, but the number of bits in the output
 * need not be a multiple of 8.
 *
 * Let || deonte concatenation with the left operand more significant
 * Let 0^{k} denote k 0 bits
 * Let |val| be the number of bits in a value
 *
 * Let G be the sha1oracle with index enc_gidx
 * Let H be the sha1oracle with index enc_hidx
 *
 * All numbers are written with the most significant byte to the left.
 * Thus, for instance 0x10 || 0x20 means 0x1020.
 *
 * When numbers are composed of C data structures, the bytes composing
 * the C data structures are interpreted little-endian order.  In
 * other words, if char a[2] = { 0x1, 0x2 } and char b[2] = { 0x40,
 * 0x80 }, then b || a means 0x80400201; the bytes in b are more
 * significant than those in a, but each of a and b is stored in
 * little-endian order in memory.  Likewise, if a = 0x12345678, then
 * running H (m) means running H on the input bytes { 0x78, 0x56,
 * 0x34, 0x12 }.
 *
 * Given as input a message "msg", and an output size "nbits",
 * pre_encrypt computes the following:
 *
 *        Mz = 0^{8*enc_zbytes} || msg
 *   padsize = nbits - |Mz|
 *         r = padsize random bits
 *        r' = 0^{-padsize % 8} || r
 *        Mg = Mz ^ first |Mz| bits of G(r')
 *        Mh = r ^ first |r| bits of H(Mg)
 *         R = Mh || Mg
 *
 * pre_encrypt returns R.
 *
 * The idea is to do something like the simpler:
 *    R = (r ^ H (Mz ^ G(r))) || (Mz ^ G(r))
 *
 * However, since the sha1oracle functions are defined in terms of
 * bytes and not bits, we prepend some 0 bits to the front of r before
 * calculating G.
 */

#include "dcinternal.h"

enum { enc_pad = 16 };
enum { enc_minz = 16 };
enum { enc_gidx = 1 };
enum { enc_hidx = 2 };

enum { sig_rndbytes = 16 };
enum { sig_minpad = 16 };
enum { sig_gidx = 3 };
enum { sigr_gidx = 4 };

void
sha1oracle_lookup (int idx, char *dst, size_t dstlen,
		   const char *src, size_t srclen)
{
  sha1oracle_ctx ora;
  sha1oracle_init (&ora, dstlen, idx);
  sha1oracle_update (&ora, src, srclen);
  sha1oracle_final (&ora, (u_char *) dst);
}

int
pre_encrypt (MP_INT *out, const char *msg, size_t nbits)
{
  size_t msglen = strlen (msg);
  char msbmask;
  size_t msgzlen, padsize, reslen;
  char *res;
  char *mp, *hp, *h;
  size_t i;

  if (msglen + enc_minz + enc_pad > nbits / 8) {
    mpz_set_ui (out, 0);
    return -1;
  }

  msbmask = 0xff >> (-nbits & 7);
  padsize = enc_pad + !!(nbits & 7);
  msgzlen = (nbits / 8) - enc_pad;

  reslen = padsize + msgzlen;
  res = malloc (reslen);
  h = malloc (padsize);
  if (!res || !h) {
    free (res);
    free (h);
    mpz_set_ui (out, 0);
    return -1;
  }
  mp = res;
  hp = mp + msgzlen;

  prng_getbytes (hp, padsize);
  hp[padsize-1] &= msbmask;
  sha1oracle_lookup (enc_gidx, mp, msgzlen, hp, padsize);
  for (i = 0; i < msglen; i++)
    mp[i] ^= msg[i];

  sha1oracle_lookup (enc_hidx, h, padsize, mp, msgzlen);
  for (i = 0; i < padsize; i++)
    hp[i] ^= h[i];
  hp[padsize-1] &= msbmask;

  mpz_set_rawmag_le (out, res, reslen);
  bzero (res, reslen);
  free (res);
  bzero (h, padsize);
  free (h);
  return 0;
}

char *
post_decrypt (const MP_INT *m, size_t nbits)
{
  const size_t msgzlen = (nbits / 8) - enc_pad;
  const size_t padsize = enc_pad + !!(nbits & 7);
  const char msbmask = 0xff >> (-nbits & 7);
  const size_t msglen = (nbits + 7) / 8;
  char *msg;
  char *mp, *hp;
  char *h, *g;
  size_t i;

  if (nbits/8 <= enc_pad + enc_minz)
    return NULL;

  msg = malloc (msglen);
  h = malloc (padsize);
  g = malloc (msgzlen);
  if (!msg || !h || !g) {
    free (msg);
    free (h);
    free (g);
    return NULL;
  }
  mpz_get_rawmag_le (msg, msglen, m);

  mp = msg;
  hp = msg + msglen - padsize;

  sha1oracle_lookup (enc_hidx, h, padsize, mp, msgzlen);
  for (i = 0; i < padsize; i++)
    hp[i] ^= h[i];
  hp[padsize-1] &= msbmask;

  sha1oracle_lookup (enc_gidx, g, msgzlen, hp, padsize);
  for (i = 0; i < msgzlen; i++)
    mp[i] ^= g[i];

  bzero (h, padsize);
  free (h);
  bzero (g, msgzlen);
  free (g);

  for (i = 0; i < msgzlen - enc_minz && mp[i]; i++)
    ;
  for (; i < msgzlen; i++)
    if (mp[i]) {
      bzero (msg, msglen);
      free (msg);
      return NULL;
    }

  return msg;
}



/*
 * pre_sign returns R from this calculation:
 *
 *   padsize = nbits - sha1::hashsize
 *         r = sig_rndbytes random bytes
 *        r' = 0^{padsize - 8*sig_rndbytes} || r
 *        M1 = SHA1 (M, r)
 *        Mg = r' ^ first padsize bytes of G(M1)
 *         R = Mg || M1
 */

int
pre_sign (MP_INT *out, sha1_ctx *sc, size_t nbits)
{
  const size_t mlen = (nbits + 7) / 8;
  const size_t padsize = mlen - sha1_hashsize;
  char r[sig_rndbytes];
  char *mp, *hp;
  int i;

  mp = malloc (mlen);
  if (!mp || nbits/8 < sig_minpad + sig_rndbytes + sha1_hashsize) {
    u_char garbage[sha1_hashsize];
    free (mp);
    sha1_final (sc, garbage);
    mpz_set_ui (out, 0);
    return -1;
  }

  prng_getbytes (r, sig_rndbytes);

  sha1_update (sc, r, sig_rndbytes);
  sha1_final (sc, (u_char *) mp);

  hp = mp + sha1_hashsize;

  sha1oracle_lookup (sig_gidx, hp, padsize, mp, sha1_hashsize);
  hp[padsize-1] &= 0xff >> (-nbits & 7);

  for (i = 0; i < sig_rndbytes; i++)
    hp[i] ^= r[i];

  mpz_set_rawmag_le (out, mp, mlen);

  bzero (mp, mlen);
  free (mp);

  return 0;
}

int
post_verify (sha1_ctx *sc, const MP_INT *s, size_t nbits)
{
  const size_t mlen = (nbits + 7) / 8;
  const size_t padsize = mlen - sha1_hashsize;
  char *mp, *hp, *g;
  u_char mrh[sha1_hashsize];
  int i;
  int ret;

  mp = malloc (mlen);
  g = malloc (padsize);
  if (!mp || !g || nbits/8 < sig_minpad + sig_rndbytes + sha1_hashsize) {
    u_char garbage[sha1_hashsize];
    free (mp);
    free (g);
    sha1_final (sc, garbage);
    return -1;
  }

  mpz_get_rawmag_le (mp, mlen, s);
  hp = mp + sha1_hashsize;

  sha1oracle_lookup (sig_gidx, g, padsize, mp, sha1_hashsize);
  g[padsize-1] &= 0xff >> (-nbits & 7);

  if (memcmp (hp + sig_rndbytes, g + sig_rndbytes, padsize - sig_rndbytes)) {
    u_char garbage[sha1_hashsize];
    free (mp);
    free (g);
    sha1_final (sc, garbage);
    return -1;
  }

  for (i = 0; i < sig_rndbytes; i++)
    hp[i] ^= g[i];
  sha1_update (sc, hp, sig_rndbytes);
  sha1_final (sc, mrh);

  ret = memcmp (mrh, mp, sizeof (mrh)) ? -1 : 0;

  bzero (g, padsize);
  free (g);
  bzero (mp, mlen);
  free (mp);

  return ret;
}

