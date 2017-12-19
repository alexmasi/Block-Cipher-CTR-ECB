/* $Id: armor.c,v 1.4 1999/07/01 15:17:46 dm Exp $ */

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

#include "dcinternal.h"

static const char b2a32[32] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '2', '3', '4', '5', '6', '7', '8', '9',
};

static const signed char a2b32[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, 24, 25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, 11, 12, -1,
  13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static const int b2a32rem[5] = {0, 2, 4, 5, 7};
static const int a2b32rem[8] = {0, -1, 1, -1, 2, 3, -1, 4};

    /*   0 1 2 3 4 5 6 7
     * 0 5 3
     * 1   2 5 1
     * 2       4 4
     * 3         1 5 2
     * 4             3 5
     */

char *
armor32 (const void *dp, size_t dl)
{
  const u_char *p = dp;
  int rem = dl % 5;
  const u_char *e = p + (dl - rem);
  size_t reslen = (dl / 5) * 8 + b2a32rem[rem];
  char *res = malloc (reslen + 1);
  char *d = res;

  if (!res)
    return NULL;

  while (p < e) {
    d[0] = b2a32[p[0] >> 3];
    d[1] = b2a32[(p[0] & 0x7) << 2 | p[1] >> 6];
    d[2] = b2a32[p[1] >> 1 & 0x1f];
    d[3] = b2a32[(p[1] & 0x1) << 4 | p[2] >> 4];
    d[4] = b2a32[(p[2] & 0xf) << 1 | p[3] >> 7];
    d[5] = b2a32[p[3] >> 2 & 0x1f];
    d[6] = b2a32[(p[3] & 0x3) << 3 | p[4] >> 5];
    d[7] = b2a32[p[4] & 0x1f];
    p += 5;
    d += 8;
  }

  switch (rem) {
  case 4:
    d[6] = b2a32[(p[3] & 0x3) << 3];
    d[5] = b2a32[p[3] >> 2 & 0x1f];
    d[4] = b2a32[(p[2] & 0xf) << 1 | p[3] >> 7];
    d[3] = b2a32[(p[1] & 0x1) << 4 | p[2] >> 4];
    d[2] = b2a32[p[1] >> 1 & 0x1f];
    d[1] = b2a32[(p[0] & 0x7) << 2 | p[1] >> 6];
    d[0] = b2a32[p[0] >> 3];
    d += 7;
    break;
  case 3:
    d[4] = b2a32[(p[2] & 0xf) << 1];
    d[3] = b2a32[(p[1] & 0x1) << 4 | p[2] >> 4];
    d[2] = b2a32[p[1] >> 1 & 0x1f];
    d[1] = b2a32[(p[0] & 0x7) << 2 | p[1] >> 6];
    d[0] = b2a32[p[0] >> 3];
    d += 5;
    break;
  case 2:
    d[3] = b2a32[(p[1] & 0x1) << 4];
    d[2] = b2a32[p[1] >> 1 & 0x1f];
    d[1] = b2a32[(p[0] & 0x7) << 2 | p[1] >> 6];
    d[0] = b2a32[p[0] >> 3];
    d += 4;
    break;
  case 1:
    d[1] = b2a32[(p[0] & 0x7) << 2];
    d[0] = b2a32[p[0] >> 3];
    d += 2;
    break;
  }

  assert (d == res + reslen);
  *d = '\0';
  return res;
}

ssize_t
armor32len (const char *_s)
{
  const u_char *s = (const u_char *) _s;
  const u_char *p = s;
  ssize_t len;
  while (a2b32[*p] >= 0)
    p++;
  len = p - s;
  return a2b32rem[len & 7] < 0 ? -1 : len;
}

ssize_t
dearmor32len (const char *s)
{
  ssize_t len = armor32len (s);
  return len < 0 ? -1 : (len >> 3) * 5 + a2b32rem[len & 7];
}

ssize_t
dearmor32 (void *out, const char *_s)
{
  const u_char *s = (const u_char *) _s;
  ssize_t len = armor32len (_s);
  int rem = a2b32rem [len & 7];
  size_t outlen = (len >> 3) * 5 + rem;
  char *d = out;
  int c0, c1, c2, c3, c4, c5, c6, c7;
  const u_char *e;

  if (rem < 0)
    return -1;
  if (len <= 0)
    return 0;

  for (e = s + (len & ~7); s < e; s += 8, d += 5) {
    c0 = a2b32[s[0]];
    c1 = a2b32[s[1]];
    d[0] = c0 << 3 | c1 >> 2;
    c2 = a2b32[s[2]];
    c3 = a2b32[s[3]];
    d[1] = c1 << 6 | c2 << 1 | c3 >> 4;
    c4 = a2b32[s[4]];
    d[2] = c3 << 4 | c4 >> 1;
    c5 = a2b32[s[5]];
    c6 = a2b32[s[6]];
    d[3] = c4 << 7 | c5 << 2 | c6 >> 3;
    c7 = a2b32[s[7]];
    d[4] = c6 << 5 | c7;
  }

  if (rem >= 1) {
    c0 = a2b32[s[0]];
    c1 = a2b32[s[1]];
    *d++ = c0 << 3 | c1 >> 2;
    if (rem >= 2) {
      c2 = a2b32[s[2]];
      c3 = a2b32[s[3]];
      *d++ = c1 << 6 | c2 << 1 | c3 >> 4;
      if (rem >= 3) {
	c4 = a2b32[s[4]];
	*d++ = c3 << 4 | c4 >> 1;
	if (rem >= 4) {
	  c5 = a2b32[s[5]];
	  c6 = a2b32[s[6]];
	  *d++ = c4 << 7 | c5 << 2 | c6 >> 3;
	}
      }
    }
  }

  assert (d == (char *) out + outlen);
  return len;
}


static const char b2a64[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/',
};

static const signed char a2b64[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

char *
armor64 (const void *dp, size_t len)
{
  const u_char *p = dp;
  int rem = len % 3;
  const u_char *e = p + (len - rem);
  size_t reslen = ((len + 2) / 3) * 4;
  char *res = malloc (reslen + 1);
  char *d = res;

  while (p < e) {
    d[0] = b2a64[p[0] >> 2];
    d[1] = b2a64[(p[0] & 0x3) << 4 | p[1] >> 4];
    d[2] = b2a64[(p[1] & 0xf) << 2 | p[2] >> 6];
    d[3] = b2a64[p[2] & 0x3f];
    d += 4;
    p += 3;
  }

  switch (rem) {
  case 1:
    d[0] = b2a64[p[0] >> 2];
    d[1] = b2a64[(p[0] & 0x3) << 4];
    d[2] = d[3] = '=';
    d += 4;
    break;
  case 2:
    d[0] = b2a64[p[0] >> 2];
    d[1] = b2a64[(p[0] & 0x3) << 4 | p[1] >> 4];
    d[2] = b2a64[(p[1] & 0xf) << 2];
    d[3] = '=';
    d += 4;
    break;
  }

  assert (d == res + reslen);
  *d = '\0';
  return res;
}

ssize_t
armor64len (const char *_s)
{
  const u_char *s = (const u_char *) _s;
  const u_char *p = s;
  ssize_t len;
  while (a2b64[*p] >= 0)
    p++;
  if (*p == '=')
    p++;
  if (*p == '=')
    p++;
  len = p - s;
  return (len & 3) ? -1 : len;
}

ssize_t
dearmor64len (const char *_s)
{
  const u_char *s = (const u_char *) _s;
  const u_char *p = s;
  ssize_t len;
  while (a2b64[*p] >= 0)
    p++;
  len = p - s;

  switch (len & 3) {
  case 0:
    return (len >> 2) * 3;
  case 2:
    return p[0] == '=' && p[1] == '=' ? (len >> 2) * 3 + 1 : -1;
  case 3:
    return p[0] == '=' ? (len >> 2) * 3 + 2 : -1;
  }
  return -1;
}

ssize_t
dearmor64 (void *out, const char *_s)
{
  const u_char *s = (const u_char *) _s;
  ssize_t outlen = dearmor64len (_s);
  ssize_t len = ((outlen + 2) / 3) * 4;
  char *d = out;
  int c0, c1, c2, c3;
  const u_char *e;

  if (outlen < 0)
    return -1;
  if (len <= 0)
    return len;

  for (e = s + len - 4; s < e; s += 4, d += 3) {
    c0 = a2b64[s[0]];
    c1 = a2b64[s[1]];
    d[0] = c0 << 2 | c1 >> 4;
    c2 = a2b64[s[2]];
    d[1] = c1 << 4 | c2 >> 2;
    c3 = a2b64[s[3]];
    d[2] = c2 << 6 | c3;
  }

  c0 = a2b64[s[0]];
  c1 = a2b64[s[1]];
  *d++ = c0 << 2 | c1 >> 4;
  if ((c2 = a2b64[s[2]]) >= 0) {
    *d++ = c1 << 4 | c2 >> 2;
    if ((c3 = a2b64[s[3]]) >= 0)
      *d++ = c2 << 6 | c3;
  }

  /*  *d = '\0'; */
  return outlen;
}
