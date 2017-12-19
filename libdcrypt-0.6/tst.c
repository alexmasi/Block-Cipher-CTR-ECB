/* $Id: tst.c,v 1.17 1999/07/08 15:48:35 dm Exp $ */

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

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <assert.h>

#include <stdio.h>
#include "dcrypt.h"

/* this was needed for MP_INT (in mpz_dump, see below), so now
 * we can do without it

#include "gmp.h"
 */

/* no need to declare this function explicitly, as now this is defined 
 * in the gmp library 

void mpz_dump (MP_INT *m);
 */

/* quick'n dirty way to inialize the pseudorandom number generator */
void
ri (void)
{
  struct {
    int pid;
    int time;
  } rid;
  rid.pid = getpid ();
  rid.time = time (NULL);
  prng_seed (&rid, sizeof (rid));
}

int
main (int argc, char **argv)
{
  ri ();

  {
    const char msg[] = "attack at dawn";
    char *s, *p;
    dckey *pk, *pk2;

    /* the default is to use hard-coded parameters;
     * let's change this and generate the params on-the-fly */

    /*
      eg_getparam = &eg_paramgen;
    */

    /* 
    pk = dckeygen (DC_ELGAMAL, 1024, NULL);
    */
    
    /* now let's try rabin */
    pk = dckeygen (DC_RABIN, 1024, NULL);

    assert (pk);
    s = dcexport_priv (pk);
    p = dcexport_pub (pk);
    printf ("Public: %s\nPrivate: %s\n", p, s);

    pk2 = dcimport_pub (p);
    assert (pk2);
    xfree (s);
    xfree (p);

    p = dcencrypt (pk2, msg);
    assert (p);
    printf ("CTEXT: %s\n", p);

    s = dcdecrypt (pk, p);
    printf ("PTEXT: %s\n", s);

    xfree (p);
    xfree (s);

    p = dcsign (pk, msg);
    assert (p);
    printf ("SIG: %s\n", p);
    assert(dcverify (pk, msg, p) != -1);
    printf ("Signature verification using private key: OK\n");
    assert(dcverify (pk2, msg, p) != -1);
    printf ("Signature verification using public key: OK\n");

    xfree (p);

    dcfree (pk);
    dcfree (pk2);
  }

  return 0;
}
