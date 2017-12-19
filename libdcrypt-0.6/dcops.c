 /* $Id: dcops.c,v 1.10 1999/07/16 15:54:37 dm Exp $ */

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

dckey *
dckeygen (const char *type, size_t k, const char *extra)
{
  const pkvtbl **vp;
  for (vp = dcconf; *vp; vp++)
    if (!strcmp (type, (*vp)->name))
      return (*vp)->keygen (k, extra);
  return NULL;
}

char *
dcexport (const dckey *key)
{
  if (key->type == PRIVATE)
    return key->vptr->serialize_priv (key);
  else if (key->type == PUBLIC)
    return key->vptr->serialize_pub (key);
  assert (0);
  return NULL;
}

char *
dcexport_priv (const dckey *key)
{
  assert (key->type == PRIVATE);
  return key->vptr->serialize_priv (key);
}

char *
dcexport_pub (const dckey *key)
{
  assert (key->type == PUBLIC || key->type == PRIVATE);
  return key->vptr->serialize_pub (key);
}

static const pkvtbl *
dclookup (const char *asc)
{
  const char *p;
  char *name;
  size_t l;
  const pkvtbl **vp;

  if (!(p = strchr (asc, ':')))
    return NULL;
  l = p - asc;
  if (!(name = malloc (l + 1)))
    return NULL;
  memcpy (name, asc, l);
  name[l] = '\0';

  for (vp = dcconf; *vp && strcmp (name, (*vp)->name); vp++)
    ;
  free (name);
  return *vp;
}

dckey *
dcimport (const char *asc)
{
  const pkvtbl *vp = dclookup (asc);
  dckey *key = NULL;
  if (vp && !(key = vp->import_priv (asc)))
    key = vp->import_pub (asc);
  return key;
}

dckey *
dcimport_priv (const char *asc)
{
  const pkvtbl *vp = dclookup (asc);
  return vp ? vp->import_priv (asc) : NULL;
}

dckey *
dcimport_pub (const char *asc)
{
  const pkvtbl *vp = dclookup (asc);
  return vp ? vp->import_pub (asc) : NULL;
}

dckey *
dckeydup (const dckey *key)
{
  dckey *k = NULL;
  char *a;
  if ((a = dcexport (key))) {
    k = dcimport (a);
    free (a);
  }
  return k;
}

void
dcfree (dckey *key)
{
  if (key->type == PRIVATE)
    key->vptr->free_priv (key);
  else if (key->type == PUBLIC)
    key->vptr->free_pub (key);
  else
    assert (0);
}

char *
dcencrypt (const dckey *key, const char *msg)
{
  assert (key->type == PUBLIC || key->type == PRIVATE);
  return key->vptr->encrypt (key, msg);
}

char *
dcdecrypt (const dckey *key, const char *msg)
{
  assert (key->type == PRIVATE);
  return key->vptr->decrypt (key, msg);
}

char *
dcsign (const dckey *key, const char *msg)
{
  assert (key->type == PRIVATE);
  return key->vptr->sign (key, msg);
}

int
dcverify (const dckey *key, const char *msg, const char *sig)
{
  assert (key->type == PUBLIC || key->type == PRIVATE);
  return key->vptr->verify (key, msg, sig);
}

int
dcispriv (const dckey *key)
{
  assert (key->type == PUBLIC || key->type == PRIVATE);
  return key->type == PRIVATE;
}

int
dcareequiv (const dckey *keya, const dckey *keyb)
{
  return (!keya) ? (!keyb) : ((!keyb) ? 0 : (!strcmp (dcexport_pub (keya),
						      dcexport_pub (keyb))));
}
