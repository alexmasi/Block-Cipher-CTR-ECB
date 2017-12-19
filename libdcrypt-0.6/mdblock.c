/* $Id: mdblock.c,v 1.4 1999/07/02 14:23:18 dm Exp $ */

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

enum { blocksize = 64 };

void
mdblock_init (mdblock *mp,
	      void (*consume) (mdblock *, const u_char block[blocksize]))
{
  mp->count = 0;
  mp->consume = consume;
}

void
mdblock_update (mdblock *mp, const void *bytes, size_t len)
{
  const u_char *data = bytes;
  size_t i;
  u_int bcount = mp->count % blocksize;

  mp->count += len;
  if (bcount + len < blocksize) {
    memcpy (&mp->buffer[bcount], data, len);
    return;
  }
  /* copy first chunk into context, do the rest (if any) */
  /* directly from data array */
  if (bcount) {
    int j = blocksize - bcount;
    memcpy (&mp->buffer[bcount], data, j);
    mp->consume (mp, mp->buffer);
    i = j;
    len -= j;
  }
  else
    i = 0;

  while (len >= blocksize) {
    mp->consume (mp, &data[i]);
    i += blocksize;
    len -= blocksize;
  }
  memcpy (mp->buffer, &data[i], len);
}

void
mdblock_finish (mdblock *mp, int bigendian)
{
  u_char *dp;
  u_char *end;
  u_int bcount = mp->count % blocksize;
  u_int64_t cnt;

  if (bcount > blocksize - 9) {
    /* need to split padding bit and count */
    u_char tmp[blocksize];
    bzero (tmp, blocksize - bcount);
    /* add padding bit */
    tmp[0] = 0x80;
    mdblock_update (mp, tmp, blocksize - bcount);
    /* don't count padding in length of string */
    mp->count -= blocksize - bcount;
    dp = mp->buffer;
  }
  else {
    dp = &mp->buffer[bcount];
    *dp++ = 0x80;
  }
  end = &mp->buffer[blocksize - 8];
  while (dp < end)
    *dp++ = 0;

  cnt = mp->count <<= 3;	/* make bytecount bitcount */

  if (bigendian) {
    *dp++ = (cnt >> 56) & 0xff;
    *dp++ = (cnt >> 48) & 0xff;
    *dp++ = (cnt >> 40) & 0xff;
    *dp++ = (cnt >> 32) & 0xff;
    *dp++ = (cnt >> 24) & 0xff;
    *dp++ = (cnt >> 16) & 0xff;
    *dp++ = (cnt >> 8) & 0xff;
    *dp = (cnt >> 0) & 0xff;
  }
  else {
    *dp++ = (cnt >> 0) & 0xff;
    *dp++ = (cnt >> 8) & 0xff;
    *dp++ = (cnt >> 16) & 0xff;
    *dp++ = (cnt >> 24) & 0xff;
    *dp++ = (cnt >> 32) & 0xff;
    *dp++ = (cnt >> 40) & 0xff;
    *dp++ = (cnt >> 48) & 0xff;
    *dp = (cnt >> 56) & 0xff;
  }

  mp->consume (mp, mp->buffer);
  /* Wipe variables */
  mp->consume = NULL;
  mp->count = 0;
  bzero (mp->buffer, sizeof (mp->buffer));
}
