/* $Id: sha1oracle.c,v 1.4 1999/07/01 15:17:47 dm Exp $ */

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
 * Sha1oracle provides a set of one-way functions that can be used in
 * some places as a substitute for a theoretical random oracle.
 *
 * The constructor takes two arguments:  The result size, and a 64-bit
 * integer designating which one way function to use from the set.
 *
 * Let || denote concatenation.
 * Let <n> designate the 64-bit big-endian representation of number n.
 *
 * Sha1oracle(size, index), when fed message M, outputs the first nbytes
 * bytes of the infinite sequence:
 *
 *   SHA1 (<0> || <index> || M) || SHA1 (<1> || <index> || M)
 *     || SHA1 (<2> || <index> || M) ...
 */

#include "dcinternal.h"

static void
sha1oracle_consume (struct mdblock *mp, const u_char block[64])
{
  sha1oracle_ctx *soc = (sha1oracle_ctx *) mp;
  size_t i;

  if (soc->firstblock) {
    u_char wblock[64];
    memcpy (wblock, block, sizeof (wblock));
    for (i = 0; i < soc->nstate; i++) {
      puthyper (wblock, i);
      sha1_transform (soc->state[i], wblock);
    }
    soc->firstblock = 0;
    return;
  }

  for (i = 0; i < soc->nstate; i++)
    sha1_transform (soc->state[i], block);
}

void
sha1oracle_init (sha1oracle_ctx *soc, size_t nbytes, u_int64_t idx)
{
  u_char prefix[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  size_t i;

  mdblock_init (&soc->mdb, sha1oracle_consume);
  puthyper (prefix + 8, idx);
  mdblock_update (&soc->mdb, prefix, sizeof (prefix));
  soc->firstblock = 1;
  soc->nbytes = nbytes;
  soc->nstate = (nbytes + 19) / 20;
  soc->state = malloc (20 * soc->nstate);
  for (i = 0; i < soc->nstate; i++)
    sha1_newstate (soc->state[i]);
} 

void
sha1oracle_update (sha1oracle_ctx *soc, const void *bytes, size_t len)
{
  mdblock_update (&soc->mdb, bytes, len);
}

void
sha1oracle_final (sha1oracle_ctx *soc, u_char *out)
{
  u_char *end = out + soc->nbytes;
  u_int i;

  mdblock_finish (&soc->mdb, 1);
  for (i = 0; i + 1 < soc->nstate; i++, out += 20)
    sha1_state2bytes (out, soc->state[i]);
  if (i < soc->nstate) {
    u_char buf[20];
    sha1_state2bytes (buf, soc->state[i]);
    memcpy (out, buf, end - out);
  }

  bzero (soc->state, soc->nstate * 20);
  free (soc->state);
  soc->state = NULL;
}
