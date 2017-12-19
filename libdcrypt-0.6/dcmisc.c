/* $Id: dcmisc.c,v 1.8 1999/07/01 18:47:38 dm Exp $ */

/*
 *
 * Copyright (C) 1999 David Mazieres (dm@uun.org)
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

#include <stdio.h>
#include <ctype.h>
#include "dcinternal.h"

void
putint (void *_dp, u_int32_t val)
{
  u_char *dp = _dp;
  dp[0] = val >> 24;
  dp[1] = val >> 16;
  dp[2] = val >> 8;
  dp[3] = val;
}

u_int32_t
getint (const void *_dp)
{
  const u_char *dp = _dp;
  return dp[0] << 24 | dp[1] << 16 | dp[2] << 8 | dp[3];
}

void
puthyper (void *_dp, u_int64_t val)
{
  u_char *dp = _dp;
  dp[0] = val >> 56;
  dp[1] = val >> 48;
  dp[2] = val >> 40;
  dp[3] = val >> 32;
  dp[4] = val >> 24;
  dp[5] = val >> 16;
  dp[6] = val >> 8;
  dp[7] = val;
}

u_int64_t
gethyper (const void *_dp)
{
  const u_char *dp = _dp;
  return (u_int64_t) dp[0] << 56 | (u_int64_t) dp[1] << 48
    | (u_int64_t) dp[2] << 40 | (u_int64_t) dp[3] << 32
    | getint (dp + 4);
}

int
cat_str (char **dstp, const char *src)
{
  char *dst = *dstp;
  size_t len = dst ? strlen (dst) : 0;
  dst = xrealloc (dst, len + strlen (src) + 1);
  if (!dst)
    return -1;
  strcpy (dst + len, src);
  *dstp = dst;
  return 0;
}

int
cat_mpz (char **dstp, const MP_INT *mp)
{
  char *a = xmalloc (mpz_sizeinbase (mp, 2) + 4);
  int res;

  if (!a)
    return -1;
  mpz_get_str (a + 2, 16, mp);
  if (mpz_sgn (mp) >= 0) {
    a[0] = '0';
    a[1] = 'x';
  }
  else {
    a[0] = '-';
    a[1] = '0';
    a[2] = 'x';
  }

  res = cat_str (dstp, a);
  free (a);
  return res;
}

int
cat_int (char **dstp, int i)
{
  char a[2 * sizeof (i) + 4];
  sprintf (a, "0x%x", i);
  return cat_str (dstp, a);
}


int
skip_str (const char **srcp, const char *str)
{
  const char *p = *srcp;
  size_t l = strlen (str);
  if (strncmp (p, str, l))
    return -1;
  *srcp = p + l;
  return 0;
}

int
read_mpz (const char **srcp, MP_INT *mp)
{
  const char *p = *srcp;
  char *q;
  const char *e;
  size_t l;
  int r;

  if (p[0] != '0' || p[1] != 'x' || !isxdigit(p[2]))
    return -1;
  e = p + 3;
  while (isxdigit (*e))
    e++;
  l = e - p;
  q = xmalloc (l + 1);
  if (!q)
    return -1;
  memcpy (q, p, l);
  q[l] = '\0';
  r = mpz_set_str (mp, q, 0);
  free (q);
  if (!r)
    *srcp = e;
  return r;
}

#ifndef xmalloc
void *
xmalloc(size_t n)
{
  void *p = malloc (n);
  if (!p) {
    fprintf (stderr, "out of memory allocating %d bytes\n", (int) n);
    abort ();
  }
  return p;
}
#endif /* !xmalloc */

#ifndef xrealloc
void *
xrealloc(void *p, size_t n)
{
  void *r = realloc (p, n);
  if (!r) {
    fprintf (stderr, "out of memory in xrealloc\n");
    abort ();
  }
  return r;
}
#endif /* !xrealloc */
