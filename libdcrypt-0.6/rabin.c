/* $Id: rabin.c,v 1.7 1999/07/08 15:02:30 dm Exp $ */

/*
 *
 * Copyright (C) 1997 David Mazieres (dm@uun.org)
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


/* Rabin-Williams public key algorithm.  From:
 *    A Modification of the RSA Public-Key Encryption Procedure.
 *    H. C. Williams, IEEE Transactions on Information Theory,
 *    Vol. IT-26, No. 6, November, 1980.
 *
 * The cipher is based on Rabin's original signature scheme.  This is
 * NOT RSA, and is NOT covered by the RSA patent.  (That's not to say
 * they couldn't try to sue you anyway for using this, but it's
 * unlikely.  However, if you use this code, you must agree to assume
 * all responsibility for patent infringement.)
 *
 * Two prime numbers p, q, chosen such that:
 *    p = 3 mod 8
 *    q = 7 mod 8
 *
 * [Note:  This means pq = 5 mod 8, so J(2, pq) = -1.]
 *
 * Define N and k as:
 *    N = pq
 *    k = 1/2 * (1/4 * (p-1) * (q-1) + 1)
 *
 * The public key is (N).
 * The private key is (N, k).
 *
 * Define the following four operations.  (Note D2 can only be
 * performed with the secret key.)
 *
 *          { 4(2M+1)       if J(2M+1, N) = 1
 * E1(M) =  { 2(2M+1)       if J(2M+1, N) = -1
 *          { key cracked!  if J(2M+1, N) = 0 (completely improbable)
 *
 * E2(M) =  M^2 % N
 *
 * D2(M) =  M^k % N
 *
 *          { (M/4-1)/2      when M = 0 mod 4
 * D1(M) =  { ((N-M)/4-1)/2  when M = 1 mod 4
 *          { (M/2-1)/2      when M = 2 mod 4
 *          { ((N-M)/2-1)/2  when M = 3 mod 4
 *
 * Public key operations on messages M < (N-4)/8:
 *   Encrypt:  E2(E1(M))
 *   Decrypt:  D1(D2(M))
 *   Sign:     D2(E1(M))
 *   Verify:   D1(E2(M))
 */

#include "dcinternal.h"

enum { rw_resvbits = 5 };

pkvtbl rabin_1;

struct rw_pub {
  dckey key;
  mpz_t n;			/* Modulus (pq) */
  size_t nbits;			/* Number of message bits */
};
typedef struct rw_pub rw_pub;

struct rw_priv {
  dckey key;
  mpz_t n;			/* Modulus (pq) */
  size_t nbits;			/* Number of message bits */
  mpz_t p;			/* Small prime */
  mpz_t q;			/* Large prime */
  mpz_t u;			/* q^(-1) mod p */
  mpz_t kp;			/* ((p-1)(q-1)+4)/8 mod p */
  mpz_t kq;			/* ((p-1)(q-1)+4)/8 mod q */
};
typedef struct rw_priv rw_priv;

static int
E1 (MP_INT *out, const MP_INT *in, const MP_INT *n)
{
  mpz_mul_2exp (out, in, 1);
  mpz_add_ui (out, out, 1);
  switch (mpz_jacobi (out, n)) {
  case 1:
    mpz_mul_2exp (out, out, 2);
    break;
  case -1:
    mpz_mul_2exp (out, out, 1);
    break;
  case 0:
    return -1;			/* key factored! */
  }
  if (mpz_cmp (out, n) >= 0)
    return -1;			/* input was too large */
  return 0;
}

static void
E2 (MP_INT *out, const MP_INT *in, const MP_INT *n)
{
  mpz_mul (out, in, in);
  mpz_mod (out, out, n);
}

/* Calculate out = in^k % n.  Use Chinese remainder theorem for speed. */
static void
D2 (MP_INT *out, const MP_INT *in, const rw_priv *sk, int rsel)
{
  mpz_t op, oq;

  mpz_init (op);
  mpz_init (oq);

  /* find op, oq such that out % p = op, out % q = oq */
  mpz_powm (op, in, sk->kp, sk->p);
  mpz_powm (oq, in, sk->kq, sk->q);

  /* rsel selects which of 4 square roots */
  if (rsel & 1)
    mpz_sub (op, sk->p, op);
  if (rsel & 2)
    mpz_sub (oq, sk->q, oq);

  /* out = (((op - oq) * u) % p) * q + oq; */
  mpz_sub (out, op, oq);
  mpz_mul (out, out, sk->u);
  mpz_mod (out, out, sk->p);
  mpz_mul (out, out, sk->q);
  mpz_add (out, out, oq);

  mpz_clear (op);
  mpz_clear (oq);
}

static void
D1 (MP_INT *out, const MP_INT *in, const MP_INT *n)
{
  switch (mpz_get_ui (in) & 3) {
  case 0:
    mpz_sub_ui (out, in, 4);
    mpz_fdiv_q_2exp (out, out, 3);
    break;
  case 1:
    mpz_sub (out, n, in);
    mpz_sub_ui (out, out, 4);
    mpz_fdiv_q_2exp (out, out, 3);
    break;
  case 2:
    mpz_sub_ui (out, in, 2);
    mpz_fdiv_q_2exp (out, out, 2);
    break;
  case 3:
    mpz_sub (out, n, in);
    mpz_sub_ui (out, out, 2);
    mpz_fdiv_q_2exp (out, out, 2);
    break;
  }
}

static char *
rw_encrypt (const dckey *key, const char *msg)
{
  const rw_pub *pk = (const rw_pub *) key;
  mpz_t m;
  char *res = NULL;

  mpz_init (m);
  if (pre_encrypt (m, msg, pk->nbits)) {
    mpz_clear (m);
    return NULL;
  }
  E1 (m, m, pk->n);
  E2 (m, m, pk->n);
  cat_mpz (&res, m);
  mpz_clear (m);
  return res;
}

static int
rw_verify (const dckey *key, const char *msg, const char *sig)
{
  const rw_pub *pk = (const rw_pub *) key;
  sha1_ctx sc;
  mpz_t m,s;
  int ret;

  mpz_init (s);
  mpz_init (m);
  if (read_mpz (&sig, s)) {
    mpz_clear (s);
    return 0;
  }
  E2 (m, s, pk->n);
  D1 (m, m, pk->n);

  sha1_init (&sc);
  sha1_update (&sc, msg, strlen (msg));
  ret = post_verify (&sc, m, pk->nbits);
  mpz_clear (s);
  mpz_clear (m);
  return ret;
}

static void
rw_free_pub (dckey *key)
{
  rw_pub *pk = (rw_pub *) key;
  mpz_clear (pk->n);
  free (pk);
}

static char *
rw_serialize_pub (const dckey *key)
{
  const rw_pub *pk = (const rw_pub *) key;
  char *res = NULL;

  if (cat_str (&res, rabin_1.name)
      || cat_str (&res, ":Pub,n=")
      || cat_mpz (&res, pk->n)) {
    free (res);
    res = NULL;
  }
  return res;
}

static dckey *
rw_import_pub (const char *asc)
{
  rw_pub *pk;

  if (skip_str (&asc, rabin_1.name)
      || skip_str (&asc, ":Pub,n="))
    return NULL;

  pk = malloc (sizeof (*pk));
  mpz_init (pk->n);
  if (read_mpz (&asc, pk->n)) {
    rw_free_pub (&pk->key);
    return NULL;
  }

  pk->key.vptr = &rabin_1;
  pk->key.type = PUBLIC;
  pk->nbits = mpz_sizeinbase2 (pk->n) - rw_resvbits;
  return &pk->key;
}

static const rw_priv *
k2priv (const dckey *key)
{
  assert (key->type == PRIVATE);
  return (rw_priv *) key;
}

static char *
rw_decrypt (const dckey *key, const char *ctext)
{
  const rw_priv *sk = k2priv (key);
  mpz_t m;
  char *ret;

  mpz_init (m);
  if (read_mpz (&ctext, m)) {
    mpz_clear (m);
    return NULL;
  }

  D2 (m, m, sk, 0);
  D1 (m, m, sk->n);
  ret = post_decrypt (m, sk->nbits);
  mpz_clear (m);
  return ret;
}

static char *
rw_sign (const dckey *key, const char *msg)
{
  const rw_priv *sk = k2priv (key);
  sha1_ctx sc;
  mpz_t m;
  char *res = NULL;

  mpz_init (m);
  sha1_init (&sc);
  sha1_update (&sc, msg, strlen (msg));
  if (pre_sign (m, &sc, sk->nbits)) {
    mpz_clear (m);
    return NULL;
  }
  E1 (m, m, sk->n);
  D2 (m, m, sk, prng_getword ());
  cat_mpz (&res, m);
  mpz_clear (m);
  return res;
}

static void
rw_free_priv (dckey *key)
{
  rw_priv *sk = (rw_priv *) k2priv (key);
  mpz_clear (sk->n);
  mpz_clear (sk->p);
  mpz_clear (sk->q);
  mpz_clear (sk->u);
  mpz_clear (sk->kp);
  mpz_clear (sk->kq);
  free (sk);
}

static int
rw_precompute (rw_priv *sk)
{
  mpz_t k, p1, q1;

  sk->key.vptr = &rabin_1;
  sk->key.type = PRIVATE;

  if (mpz_cmp (sk->p, sk->q) > 0) {
    /* Make sk->p < sk->q to make sk->u as small as possible */
    *k = *sk->p;
    *sk->p = *sk->q;
    *sk->q = *k;
  }

  /* Calculate modulus N = pq */
  mpz_mul (sk->n, sk->p, sk->q);
  sk->nbits = mpz_sizeinbase2 (sk->n);
  if (sk->nbits <= rw_resvbits)
    return -1;
  sk->nbits -= rw_resvbits;

  mpz_init (k);
  mpz_init (p1);
  mpz_init (q1);

  /* Calculate k = ((p-1)(q-1)/4 + 1)/2 = ((p-1)(q-1) + 4)/8 */
  mpz_sub_ui (p1, sk->p, 1);
  mpz_sub_ui (q1, sk->q, 1);
  mpz_mul (k, p1, q1);
  mpz_add_ui (k, k, 4);
  mpz_fdiv_q_2exp (k, k, 3);

  /* Calculate kp = k % (p-1), and kq = k % (q-1) */
  mpz_mod (sk->kp, k, p1);
  mpz_mod (sk->kq, k, q1);

  /* Calculate u such that (uq) % p = 1 */
  mpz_invert (sk->u, sk->q, sk->p);

  mpz_clear (k);
  mpz_clear (p1);
  mpz_clear (q1);

  return 0;
}

static const char rwak_ppref[] = ":Priv,p=";
static const char rwak_qpref[] = ",q=";

static char *
rw_serialize_priv (const dckey *key)
{
  const rw_priv *sk = k2priv (key);
  size_t buflen = (strlen (rabin_1.name)
		   + sizeof (rwak_ppref) + sizeof (rwak_qpref) + 3
		   + mpz_sizeinbase (sk->p, 16)
		   + mpz_sizeinbase (sk->q, 16));
  char *buf = malloc (buflen);
  char *p = buf;

  if (!buf)
    return NULL;

  strcpy (p, rabin_1.name);
  strcat (p, rwak_ppref);
  strcat (p, "0x");
  p += strlen (p);
  mpz_get_str (p, 16, sk->p);
  strcat (p, rwak_qpref);
  strcat (p, "0x");
  p += strlen (p);
  mpz_get_str (p, 16, sk->q);

  p += strlen (p) + 1;
  assert (p == buf + buflen);

  return buf;
}

static dckey *
rw_import_priv (const char *asc)
{
  rw_priv *sk;

  if (skip_str (&asc, rabin_1.name)
      || skip_str (&asc, rwak_ppref)
      || !(sk = malloc (sizeof (*sk))))
    return NULL;

  mpz_init (sk->n);
  mpz_init (sk->p);
  mpz_init (sk->q);
  mpz_init (sk->u);
  mpz_init (sk->kp);
  mpz_init (sk->kq);

  if (read_mpz (&asc, sk->p)
      || skip_str (&asc, rwak_qpref)
      || read_mpz (&asc, sk->q)
      || rw_precompute (sk)) {
    sk->key.type = PRIVATE;
    rw_free_priv (&sk->key);
    return NULL;
  }

  return &sk->key;
}

static dckey *
rw_keygen (size_t nbits, const char *extra)
{
  rw_priv *sk = malloc (sizeof (*sk));
  int bit2;

  if (!sk)
    return NULL;

  mpz_init (sk->n);
  mpz_init (sk->p);
  mpz_init (sk->q);
  mpz_init (sk->u);
  mpz_init (sk->kp);
  mpz_init (sk->kq);

  do {
    random_bigint (sk->p, (nbits+1)/2);
    mpz_setbit (sk->p, 0);
    mpz_setbit (sk->p, 1);
  } while (!primecheck (sk->p));

  bit2 = ~mpz_get_ui (sk->p) & 4;
  do {
    random_bigint (sk->q, nbits/2);
    mpz_setbit (sk->q, 0);
    mpz_setbit (sk->q, 1);
    if (bit2)
      mpz_setbit (sk->q, 2);
    else
      mpz_clrbit (sk->q, 2);
  } while (!primecheck (sk->q));

  rw_precompute (sk);
  return &sk->key;
}

pkvtbl rabin_1 = {
  "Rabin-1",

  rw_encrypt,
  rw_verify,
  rw_serialize_pub,
  rw_free_pub,
  rw_import_pub,

  rw_decrypt,
  rw_sign,
  rw_serialize_priv,
  rw_free_priv,
  rw_import_priv,

  rw_keygen
};
