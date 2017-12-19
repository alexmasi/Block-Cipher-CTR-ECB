/* $Id: mpz_raw.c,v 1.4 1999/06/30 16:39:22 dm Exp $ */

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

#undef GMP_LIMB_SIZE
#define GMP_LIMB_SIZE sizeof (mp_limb_t)

#undef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#undef ABS
#define ABS(a) ((a) < 0 ? -(a) : (a))

size_t
mpz_sizeinbase2 (const MP_INT *mp)
{
  if (mpz_sgn (mp))
    return mpz_sizeinbase (mp, 2);
  else
    return 0;
}

int
mpz_getbit (const MP_INT *mp, size_t bit)
{
  long limb = bit / (8 * GMP_LIMB_SIZE);
  long nlimbs = mp->_mp_size;
  if (mp->_mp_size >= 0) {
    if (limb >= nlimbs)
      return 0;
    return mp->_mp_d[limb] >> bit % (8 * GMP_LIMB_SIZE) & 1;
  }
  else {
    int carry;
    mp_limb_t *p, *e;

    nlimbs = -nlimbs;
    if (limb >= nlimbs)
      return 1;

    carry = 1;
    p = mp->_mp_d;
    e = p + limb;
    for (; p < e; p++)
      if (*p) {
	carry = 0;
	break;
      }
    return (~*e + carry) >> bit % (8 * GMP_LIMB_SIZE) & 1;
  }
}


void
assert_limb_size ()
{
  switch (0) {
  case 0:
  case (GMP_LIMB_SIZE == 8 || GMP_LIMB_SIZE == 4 || GMP_LIMB_SIZE == 2):
    break;
  }
}

#define COPYLIMB_BYTE(dst, src, SW, n) \
  ((char *) (dst))[n] = ((char *) (src))[SW (n)]

#define LSWAP(n) ((n & -GMP_LIMB_SIZE) + GMP_LIMB_SIZE-1 - n % GMP_LIMB_SIZE)
#define NSWAP(n) n

#define COPYLIMB(dst, src, SW)			\
do {						\
  switch (GMP_LIMB_SIZE) {			\
  case 8:					\
    COPYLIMB_BYTE (dst, src, SW, 7);		\
    COPYLIMB_BYTE (dst, src, SW, 6);		\
    COPYLIMB_BYTE (dst, src, SW, 5);		\
    COPYLIMB_BYTE (dst, src, SW, 4);		\
  case 4:					\
    COPYLIMB_BYTE (dst, src, SW, 3);		\
    COPYLIMB_BYTE (dst, src, SW, 2);		\
  case 2:					\
    COPYLIMB_BYTE (dst, src, SW, 1);		\
    COPYLIMB_BYTE (dst, src, SW, 0);		\
  }						\
} while (0)

static const mp_limb_t letest = 1;
#define is_little_endian (*(char *)&letest)

#define COPYLIMB_LE(dst, src)			\
do {						\
  if (is_little_endian)				\
    COPYLIMB (dst, src, NSWAP);			\
  else						\
    COPYLIMB (dst, src, LSWAP);			\
} while (0)

#define COPYLIMB_BE(dst, src)			\
do {						\
  if (is_little_endian)				\
    COPYLIMB (dst, src, LSWAP);			\
  else						\
    COPYLIMB (dst, src, NSWAP);			\
} while (0)


void
mpz_get_rawmag_le (char *buf, size_t size, const MP_INT *mp)
{
  char *bp = buf;
  const mp_limb_t *sp = mp->_mp_d;
  const mp_limb_t *ep = sp + min (size / GMP_LIMB_SIZE,
				  (size_t) ABS (mp->_mp_size));
  size_t n;
  char *e;

  while (sp < ep) {
    COPYLIMB_LE (bp, sp);
    bp += GMP_LIMB_SIZE;
    sp++;
  }
  n = size - (bp - buf);
  if (n < GMP_LIMB_SIZE && sp < mp->_mp_d + ABS (mp->_mp_size)) {
    mp_limb_t v = *sp;
    for (e = bp + n; bp < e; v >>= 8)
      *bp++ = v;
  }
  else
    bzero (bp, n);
}

void
mpz_get_rawmag_be (char *buf, size_t size, const MP_INT *mp)
{
  char *bp = buf + size;
  const mp_limb_t *sp = mp->_mp_d;
  const mp_limb_t *ep = sp + min (size / GMP_LIMB_SIZE,
				  (size_t) ABS (mp->_mp_size));
  size_t n;

  while (sp < ep) {
    bp -= GMP_LIMB_SIZE;
    COPYLIMB_BE (bp, sp);
    sp++;
  }
  n = bp - buf;
  if (n < GMP_LIMB_SIZE && sp < mp->_mp_d + ABS (mp->_mp_size)) {
    mp_limb_t v = *sp;
    for (; bp > buf; v >>= 8)
      *--bp = v;
  }
  else
    bzero (buf, n);
}

void
mpz_set_rawmag_le (MP_INT *mp, const char *buf, size_t size)
{
  const char *bp = buf;
  size_t nlimbs = (size + sizeof (mp_limb_t)) / sizeof (mp_limb_t);
  mp_limb_t *sp;
  mp_limb_t *ep;
  const char *ebp;

  mp->_mp_size = nlimbs;
  if (nlimbs > (u_long) mp->_mp_alloc)
    _mpz_realloc (mp, nlimbs);
  sp = mp->_mp_d;
  ep = sp + size / sizeof (mp_limb_t);

  while (sp < ep) {
    COPYLIMB_LE (sp, bp);
    bp += GMP_LIMB_SIZE;
    sp++;
  }

  ebp = buf + size;
  if (bp < ebp) {
    mp_limb_t v = (u_char) *--ebp;
    while (bp < ebp)
      v = v << 8 | (u_char) *--ebp;
    *sp++ = v;
  }

  while (sp > mp->_mp_d && !sp[-1])
    sp--;
  mp->_mp_size = sp - mp->_mp_d;
}

void
mpz_set_rawmag_be (MP_INT *mp, const char *buf, size_t size)
{
  const char *bp = buf + size;
  size_t nlimbs = (size + sizeof (mp_limb_t)) / sizeof (mp_limb_t);
  mp_limb_t *sp;
  mp_limb_t *ep;

  mp->_mp_size = nlimbs;
  if (nlimbs > (u_long) mp->_mp_alloc)
    _mpz_realloc (mp, nlimbs);
  sp = mp->_mp_d;
  ep = sp + size / sizeof (mp_limb_t);

  while (sp < ep) {
    bp -= GMP_LIMB_SIZE;
    COPYLIMB_BE (sp, bp);
    sp++;
  }

  if (bp > buf) {
    mp_limb_t v = (u_char) *buf++;
    while (bp > buf) {
      v <<= 8;
      v |= (u_char) *buf++;
    }
    *sp++ = v;
  }

  while (sp > mp->_mp_d && !sp[-1])
    sp--;
  mp->_mp_size = sp - mp->_mp_d;
}
