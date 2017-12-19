/* $Id: prng.c,v 1.4 1999/06/30 16:39:22 dm Exp $ */

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

#include "dcinternal.h"

static u_int32_t prng_state[16];

static const u_int32_t initdat[5] = {
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

void
prng_transform (u_int32_t state[64], u_int32_t out[5])
{
  int c, i;
  memcpy (out, initdat, sizeof (initdat));
  sha1_transform (out, (u_char *) state);

  for (c = 0, i = 0; i < 5; i++) {
    u_int64_t res = state[i] + out[i] + c;
    state[i] = res;
    c = res >> 32;
  }
}

void
prng_getbytes (void *buf, size_t len)
{
  char *cp = buf;
  u_int32_t out[5];

  while (len >= sizeof (out)) {
    prng_transform (prng_state, out);
    memcpy (cp, out, sizeof (out));
    cp += sizeof (out);
    len -= sizeof (out);
  }
  if (len > 0) {
    prng_transform (prng_state, out);
    memcpy (cp, out, len);
  }
  bzero (out, sizeof (out));
}

u_int32_t
prng_getword (void)
{
  u_int32_t ret;
  prng_getbytes (&ret, sizeof (ret));
  return ret;
}

u_int64_t 
prng_gethyper (void) 
{
  u_int64_t ret;
  prng_getbytes (&ret, sizeof (ret));
  return ret;
}

void
prng_getfrom_zn (mpz_t ret, const mpz_t n)
{

  int bits;
  size_t len;
  u_char *buf = NULL;

  assert (mpz_sgn (n) > 0);
  bits = mpz_sizeinbase2 (n);
  len = (bits + 7) >> 3;
  buf = (u_char *) xmalloc (len);
  bzero (buf, len);

  do {
    prng_getbytes (buf, len);
    buf[0] &= 0xff >> (-bits & 7);
    mpz_set_rawmag_be (ret, (char *) buf, len);
    bzero (buf, len);
  } while (mpz_cmp (ret, n) >= 0);

  xfree (buf);
}

void
prng_seed (void *buf, size_t len)
{
  u_char oldstate[sizeof (prng_state)];
  sha1oracle_ctx soc;

  sha1oracle_init (&soc, sizeof (prng_state), 0);
  prng_getbytes (oldstate, sizeof (oldstate));
  sha1oracle_update (&soc, oldstate, sizeof (oldstate));
  bzero (oldstate, sizeof (oldstate));
  sha1oracle_update (&soc, buf, len);
  sha1oracle_final (&soc, (u_char *) prng_state);
}
