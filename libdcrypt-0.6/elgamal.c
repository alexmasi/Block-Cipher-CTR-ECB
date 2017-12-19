/* $Id: elgamal.c,v 1.3 1999/07/08 15:02:30 dm Exp $ */

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

pkvtbl elgamal_1;

struct egpub {
  dckey key;
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
  size_t nbits;
};
typedef struct egpub egpub;

struct egpriv {
  struct egpub pub;
  mpz_t x;			/* secret x */
};
typedef struct egpriv egpriv;

static int
msg_to_sig_mpz (MP_INT *out, const char *msg, size_t nbits)
{
  const size_t buflen = (nbits + 7) / 8;
  char *buf = malloc (buflen);
  if (!buf) {
    mpz_set_ui (out, 0);
    return -1;
  }
  sha1oracle_lookup (5, buf, buflen, msg, strlen (msg));
  mpz_set_rawmag_le (out, buf, buflen);
  mpz_tdiv_r_2exp (out, out, nbits);
  return 0;
}

static char *
eg_encrypt (const dckey *key, const char *msg)
{
  egpub *pk = (egpub *) key;
  mpz_t m;
  mpz_t r;
  mpz_t t;
  char *res = NULL;

  mpz_init (m);
  if (pre_encrypt (m, msg, pk->nbits)) {
    mpz_clear (m);
    return NULL;
  }

  mpz_init (r);
  mpz_init (t);

  random_zn (r, pk->q);
  mpz_powm (t, pk->y, r, pk->p);
  mpz_mul (t, t, m);
  mpz_mod (t, t, pk->p);
  mpz_powm (r, pk->g, r, pk->p);

  if (cat_str (&res, "r=")
      || cat_mpz (&res, r)
      || cat_str (&res, ",t=")
      || cat_mpz (&res, t)) {
    free (res);
    res = NULL;
  }

  mpz_clear (t);
  mpz_clear (r);
  mpz_clear (m);
  return res;
}

static int
eg_verify (const dckey *key, const char *msg, const char *sig)
{
  egpub *pk = (egpub *) key;
  mpz_t m, r, s, t;
  int ret = -1;

  mpz_init (m);
  mpz_init (r);
  mpz_init (s);
  mpz_init (t);

  if (msg_to_sig_mpz (m, msg, pk->nbits)
      || skip_str (&sig, "r=")
      || read_mpz (&sig, r)
      || skip_str (&sig, ",s=")
      || read_mpz (&sig, s))
    goto leave;

  mpz_powm (m, pk->g, m, pk->p);

  mpz_powm (t, pk->y, r, pk->p);
  mpz_powm (r, r, s, pk->p);
  mpz_mul (t, t, r);
  mpz_mod (t, t, pk->p);

  ret = mpz_cmp (m, t) ? -1 : 0;

 leave:
  mpz_clear (t);
  mpz_clear (s);
  mpz_clear (r);
  mpz_clear (m);
  return ret;
}

static char *
eg_serialize_pub (const dckey *key)
{
  egpub *pk = (egpub *) key;
  char *res = NULL;

  if (cat_str (&res, elgamal_1.name)
      || cat_str (&res, ":Pub,p=")
      || cat_mpz (&res, pk->p)
      || cat_str (&res, ",q=")
      || cat_mpz (&res, pk->q)
      || cat_str (&res, ",g=")
      || cat_mpz (&res, pk->g)
      || cat_str (&res, ",y=")
      || cat_mpz (&res, pk->y)) {
    free (res);
    return NULL;
  }
  return res;
}

static void
eg_free_pub (dckey *key)
{
  egpub *pk = (egpub *) key;
  key->type = 0;
  mpz_clear (pk->p);
  mpz_clear (pk->g);
  mpz_clear (pk->y);
  free (pk);
}

static dckey *
eg_import_pub (const char *asc)
{
  egpub *pk;

  if (skip_str (&asc, elgamal_1.name)
      || skip_str (&asc, ":Pub,p="))
    return NULL;

  if (!(pk = malloc (sizeof (*pk))))
    return NULL;
  pk->key.vptr = &elgamal_1;
  pk->key.type = PUBLIC;
  mpz_init (pk->p);
  mpz_init (pk->q);
  mpz_init (pk->g);
  mpz_init (pk->y);

  if (read_mpz (&asc, pk->p)
      || skip_str (&asc, ",q=")
      || read_mpz (&asc, pk->q)
      || skip_str (&asc, ",g=")
      || read_mpz (&asc, pk->g)
      || skip_str (&asc, ",y=")
      || read_mpz (&asc, pk->y)) {
    eg_free_pub (&pk->key);
    return NULL;
  }

  pk->nbits = mpz_sizeinbase2 (pk->p) - 1;
  return &pk->key;
}

static const egpriv *
k2priv (const dckey *key)
{
  assert (key->type == PRIVATE);
  return (egpriv *) key;
}

static char *
eg_decrypt (const dckey *key, const char *ctext)
{
  const egpriv *sk = k2priv (key);
  mpz_t r, t;
  char *res = NULL;

  mpz_init (r);
  mpz_init (t);

  if (skip_str (&ctext, "r=")
      || read_mpz (&ctext, r)
      || skip_str (&ctext, ",t=")
      || read_mpz (&ctext, t))
    goto leave;

  mpz_powm (r, r, sk->x, sk->pub.p);
  mpz_invert (r, r, sk->pub.p);
  mpz_mul (t, t, r);
  mpz_mod (t, t, sk->pub.p);
  res = post_decrypt (t, sk->pub.nbits);

 leave:
  mpz_clear (r);
  mpz_clear (t);
  return res;
}

char *
eg_sign (const dckey *key, const char *msg)
{
  const egpriv *sk = k2priv (key);
  char *res = NULL;
  mpz_t m, k, ki, r, s;

  mpz_init (m);
  mpz_init (k);
  mpz_init (ki);
  mpz_init (r);
  mpz_init (s);

  if (msg_to_sig_mpz (m, msg, sk->pub.nbits))
    goto leave;

  do {
    random_zn (k, sk->pub.q);
  } while (!mpz_invert (ki, k, sk->pub.q));

  mpz_powm (r, sk->pub.g, k, sk->pub.p);

  mpz_mul (s, sk->x, r);
  mpz_mod (s, s, sk->pub.q);
  mpz_neg (s, s);
  mpz_add (s, s, m);
  mpz_mul (s, s, ki);
  mpz_mod (s, s, sk->pub.q);

  if (cat_str (&res, "r=")
      || cat_mpz (&res, r)
      || cat_str (&res, ",s=")
      || cat_mpz (&res, s)) {
    free (res);
    res = NULL;
  }

 leave:
  mpz_clear (s);
  mpz_clear (r);
  mpz_clear (ki);
  mpz_clear (k);
  mpz_clear (m);
  return res;
}

static char *
eg_serialize_priv (const dckey *key)
{
  const egpriv *sk = k2priv (key);
  char *res = NULL;

  /* XXX - cat_str and cat_mpz don't wipe memory when reallocating! */
  if (cat_str (&res, elgamal_1.name)
      || cat_str (&res, ":Priv,p=")
      || cat_mpz (&res, sk->pub.p)
      || cat_str (&res, ",q=")
      || cat_mpz (&res, sk->pub.q)
      || cat_str (&res, ",g=")
      || cat_mpz (&res, sk->pub.g)
      || cat_str (&res, ",x=")
      || cat_mpz (&res, sk->x)) {
    free (res);
    return NULL;
  }
  return res;
}

static void
eg_free_priv (dckey *key)
{
  egpriv *sk = (egpriv *) k2priv (key);
  key->type = 0;
  mpz_clear (sk->pub.p);
  mpz_clear (sk->pub.q);
  mpz_clear (sk->pub.g);
  mpz_clear (sk->pub.y);
  mpz_clear (sk->x);
  free (sk);
}

static dckey *
eg_import_priv (const char *asc)
{
  egpriv *sk;

  if (skip_str (&asc, elgamal_1.name)
      || skip_str (&asc, ":Priv,p="))
    return NULL;

  if (!(sk = malloc (sizeof (*sk))))
    return NULL;
  sk->pub.key.vptr = &elgamal_1;
  sk->pub.key.type = PRIVATE;
  mpz_init (sk->pub.p);
  mpz_init (sk->pub.q);
  mpz_init (sk->pub.g);
  mpz_init (sk->pub.y);
  mpz_init (sk->x);

  if (read_mpz (&asc, sk->pub.p)
      || skip_str (&asc, ",q=")
      || read_mpz (&asc, sk->pub.q)
      || skip_str (&asc, ",g=")
      || read_mpz (&asc, sk->pub.g)
      || skip_str (&asc, ",x=")
      || read_mpz (&asc, sk->x)) {
    eg_free_priv (&sk->pub.key);
    return NULL;
  }

  mpz_powm (sk->pub.y, sk->pub.g, sk->x, sk->pub.p);
  sk->pub.nbits = mpz_sizeinbase2 (sk->pub.p) - 1;
  return &sk->pub.key;
}

static dckey *
eg_keygen (size_t nbits, const char *extra)
{
  egpriv *sk;

  if (!extra && !(extra = eg_getparam (nbits)))
    return NULL;
  if (!(sk = malloc (sizeof (*sk))))
    return NULL;

  sk->pub.key.vptr = &elgamal_1;
  sk->pub.key.type = PRIVATE;
  mpz_init (sk->pub.p);
  mpz_init (sk->pub.q);
  mpz_init (sk->pub.g);
  mpz_init (sk->pub.y);
  mpz_init (sk->x);

  if (skip_str (&extra, "p=")
      || read_mpz (&extra, sk->pub.p)
      || skip_str (&extra, ",q=")
      || read_mpz (&extra, sk->pub.q)
      || skip_str (&extra, ",g=")
      || read_mpz (&extra, sk->pub.g)) {
    eg_free_priv (&sk->pub.key);
    return NULL;
  }

  random_zn (sk->x, sk->pub.q);
  mpz_powm (sk->pub.y, sk->pub.g, sk->x, sk->pub.p);
  sk->pub.nbits = mpz_sizeinbase2 (sk->pub.p) - 1;
  return &sk->pub.key;
}

const char *
eg_paramgen (size_t nbits)
{
  mpz_t p, q, t;
  char *res = NULL;
  int i;

  mpz_init (p);
  mpz_init (q);
  mpz_init (t);

 restart:
  do {
    random_bigint (p, nbits);
    mpz_setbit (p, 0);
  } while (!sprimecheck (p, q));

  for (i = 0;; i++) {
    if (i == num_small_primes)
      goto restart;
    mpz_set_ui (t, small_primes[i]);
    mpz_powm (t, t, q, p);
    if (mpz_cmp_ui (t, 1))
      break;
  }

  if (cat_str (&res, "p=")
      || cat_mpz (&res, p)
      || cat_str (&res, ",q=")
      || cat_mpz (&res, q)
      || cat_str (&res, ",g=")
      || cat_int (&res, small_primes[i])) {
    free (res);
    res = NULL;
  }
  mpz_clear (t);
  mpz_clear (q);
  mpz_clear (p);
  return res;
}

pkvtbl elgamal_1 = {
  "Elgamal-1",

  eg_encrypt,
  eg_verify,
  eg_serialize_pub,
  eg_free_pub,
  eg_import_pub,

  eg_decrypt,
  eg_sign,
  eg_serialize_priv,
  eg_free_priv,
  eg_import_priv,

  eg_keygen
};

const char *
eg_getparam_default (size_t nbits)
{
  if (nbits <= 512)
    return "p=0xb245175135ea14dbd127d62d75ec4e7f65389f32030dc0555c894ced21f30b8f11b289c03f3e6dac015ad600cfaebcb0e7a61c8a015262092b108a090669e967,q=0xb245175135ea14dbd127d62d75ec4e7f65389f32030dc0555c894ced21f30b8f11b289c03f3e6dac015ad600cfaebcb0e7a61c8a015262092b108a090669e966,g=0x7";
  else if (nbits <= 1024)
    return "p=0xf79f1bc68ff0853731fcdf48c726fcd0fd7d67787865d1022d3e6ae51b26db9486307c77040f44229c772b392c9f98a9028bfbc3cc71966511d89a947ae0d87ea8fccfcc3d67a426d8179e5dacac5648c208324e29166a153736e2dd0a619781609a8b94e52fcf0ba5f4c4cb8f4471cdaa7530737521b06f1251d466144c2d03,q=0xf79f1bc68ff0853731fcdf48c726fcd0fd7d67787865d1022d3e6ae51b26db9486307c77040f44229c772b392c9f98a9028bfbc3cc71966511d89a947ae0d87ea8fccfcc3d67a426d8179e5dacac5648c208324e29166a153736e2dd0a619781609a8b94e52fcf0ba5f4c4cb8f4471cdaa7530737521b06f1251d466144c2d02,g=0xb";
  else if (nbits <= 1536)
    return "p=0xa7b27159e51587b4dbce4e9e12e8bc256adb08570277e153919dcea1afa6fc293fc07f1a0d552fc34c782b4ec11320f706559281a44b83ebbf92af4b51a1f8c782e9e2cccf7fbe81b42db09ef1028fe3d270b5a89c85618ef97cc6d6a7324f9d77d35d311230d3b542ddcad16be81eac369d5466c163d5c9e919635362cf5291d2c0d0d313ae5630f137bad3094d977f2d729ac7aa7bfd2c338d773d084d0b651c312778fb08a77e40eb8cdf1022e7f83de3f6ce5fbe6868de10a22713b39887,q=0xa7b27159e51587b4dbce4e9e12e8bc256adb08570277e153919dcea1afa6fc293fc07f1a0d552fc34c782b4ec11320f706559281a44b83ebbf92af4b51a1f8c782e9e2cccf7fbe81b42db09ef1028fe3d270b5a89c85618ef97cc6d6a7324f9d77d35d311230d3b542ddcad16be81eac369d5466c163d5c9e919635362cf5291d2c0d0d313ae5630f137bad3094d977f2d729ac7aa7bfd2c338d773d084d0b651c312778fb08a77e40eb8cdf1022e7f83de3f6ce5fbe6868de10a22713b39886,g=0x11";
  else if (nbits <= 2048)
    return "p=0xb4d69648db452dd3e524a00000fa7dedc8f791decc0799335a482a296d49c21be4c63fb8c63e3025a10d3941ab64cd48b6aeceeef60d3a2dd7fb88a12364f04ef12617aac6ddac210733cff641fd595d569b1e8c62cde8d09277202e026a4aeda1d4b7b5c0ac99a1276b87b9864855ebc242015a99e79016c8bee4d65c3b30e0272e1cb8ebd12aa0ce533bbd72aafbb2fe9cd750e732e3b07d399e1f5b62a106c08bd6cf4aa99ebb4e33be9f34fd3da57d936fd31916478f5e73adc113519684ef15721b510ac0165f4d0f5e72b923223d0c39f6004780dca0c74e80cbf00ed7915e777f9a7a38bab9201b8f3318f5ab1a7c3a2993f96beb3f091670d7c20927,g=0x5";
  else if (nbits <= 4096)
    return "p=0xd6d3bb04176bddf6c602f7501041273b2d4c9f79eb956c8f6326d37766983d06bf64b004e77b65165a34faf25bdf22f0cfaa946013c1b65b61a037b8683603ebd265d4694696f3676b966a6231374f16aa00343d2f1450b9e18c4753c8d3397cc98852e24a723f421068e1d1010ba70abf740c7e6b232778113220e06b3db5589bae66a5393acba971bbda0eefbe7708c5107eb8ae4ec4f00fb34c36db17f395c6617d20cce60558a0609f514fb9a261ddf44574321ed4364639cf0ad2e3d287a640f9ece71ddb708619ded719f950687bc6734cd5b4ac4f4942047319820b533b06b03f2ce7b62c17141354c86d873c01e5c3fd261050706bd3386bc8db96c5695713a1fa8f6676628bc31691a3b00966eaa16cb508855df9ee0f2d52c083f10c8bc3fc8eec2970ed06bfdeb9ef86371996966d556507b4823eeaee17c1f2d668e21715ee18c79ec80650f9011378c062321fb93724381fef05d61d4f118864a89c26e1217173ac9f0439b2fb9b30bc0a5294dc2f42a9daf7283e5f20039ce17c85ab127ba28bba93c6d39a8e5c57e17ff4ebf54b15370df182c035c12411e0f95c573d3ffdfde8295b5f59d4f667655d56b9d490711df779e0defd18e5ac7a230cf28beda40aef8e82f3aa2da8a4740ad98e3cd631188f921d3e5bf3d60b16cdd119052740326ab563e2743a5b43c796da779d27ea18cb3dcc160f637faa0b,q=0xd6d3bb04176bddf6c602f7501041273b2d4c9f79eb956c8f6326d37766983d06bf64b004e77b65165a34faf25bdf22f0cfaa946013c1b65b61a037b8683603ebd265d4694696f3676b966a6231374f16aa00343d2f1450b9e18c4753c8d3397cc98852e24a723f421068e1d1010ba70abf740c7e6b232778113220e06b3db5589bae66a5393acba971bbda0eefbe7708c5107eb8ae4ec4f00fb34c36db17f395c6617d20cce60558a0609f514fb9a261ddf44574321ed4364639cf0ad2e3d287a640f9ece71ddb708619ded719f950687bc6734cd5b4ac4f4942047319820b533b06b03f2ce7b62c17141354c86d873c01e5c3fd261050706bd3386bc8db96c5695713a1fa8f6676628bc31691a3b00966eaa16cb508855df9ee0f2d52c083f10c8bc3fc8eec2970ed06bfdeb9ef86371996966d556507b4823eeaee17c1f2d668e21715ee18c79ec80650f9011378c062321fb93724381fef05d61d4f118864a89c26e1217173ac9f0439b2fb9b30bc0a5294dc2f42a9daf7283e5f20039ce17c85ab127ba28bba93c6d39a8e5c57e17ff4ebf54b15370df182c035c12411e0f95c573d3ffdfde8295b5f59d4f667655d56b9d490711df779e0defd18e5ac7a230cf28beda40aef8e82f3aa2da8a4740ad98e3cd631188f921d3e5bf3d60b16cdd119052740326ab563e2743a5b43c796da779d27ea18cb3dcc160f637faa0a,g=0x2";
  else
    return NULL;
}

const char *(*eg_getparam) (size_t nbits) = eg_getparam_default;

/* faster parameter generator */
/* adapted from schnorr.C in the SFS distribution */

#define DIV_ROUNDUP(p,q) (((p) + ((q) - 1)) / (q))
#define PRIMETEST_ITER 25

void
gen_q (mpz_t q, u_int64_t *seed, u_int seedsize)
{
  mpz_t u1, u2;
  char digest[sha1_hashsize];

  mpz_init (u1);
  mpz_init (u2);

  do {
    sha1_hash (digest, seed, seedsize << 3);
    mpz_set_rawmag_le (u1, digest, sha1_hashsize);
    seed[3]++; /* this is specific to sha1_hashsize = 20 ... */
    sha1_hash (digest, seed, seedsize << 3); 
    mpz_set_rawmag_le (u2, digest, sha1_hashsize);
    mpz_xor (q, u1, u2);

    /* q should be big and odd, so we set both the high and the low bits */
    mpz_setbit (q, (sha1_hashsize << 3) - 1); /* this also is specific ... */
    mpz_setbit (q, 0);
  } while (!mpz_probab_prime_p (q, 5)); /* more checks on q later ... */

  mpz_clear (u1);
  mpz_clear (u2);
}

void
gen_p (mpz_t p, char *raw_p, const MP_INT *q, size_t nbits, 
       u_int64_t *seed, u_int seedsize)
{
  u_int off;
  u_int pbytes = nbits >> 3;
  u_int raw_psize = (DIV_ROUNDUP (pbytes, sha1_hashsize)) * sha1_hashsize;
  mpz_t X, c, qq; 

  mpz_init (X);
  mpz_init (c);
  mpz_init (qq);

  /* qq is q * q */
  mpz_mul (qq, q, q);

  do {
    for (off = 0; off < raw_psize; off += sha1_hashsize) {
      seed[0]++;
      sha1_hash (raw_p + off, seed, seedsize << 3);
    }
    mpz_set_rawmag_le (X, raw_p, pbytes);
    mpz_setbit (X, nbits - 1);
    mpz_mod (c, X, qq);
    mpz_add_ui (p, X, 1);
    mpz_sub (p, p, c);
  } while (!mpz_probab_prime_p (p, PRIMETEST_ITER));

  mpz_clear (X);
  mpz_clear (c);
  mpz_clear (qq);
}

void
gen_g (mpz_t g, const MP_INT *p, const MP_INT *q, 
       u_int64_t *seed, u_int seedsize)
{
  mpz_t p_3, e, h;

  mpz_init (p_3);
  mpz_init (e);
  mpz_init (h);

  mpz_sub_ui (p_3, p, 3);

  mpz_sub_ui (e, p, 1);
  mpz_fdiv_q (e, e, q);

  do {
    random_zn (h, p_3);
    mpz_add_ui (h, h, 1);
    mpz_powm (g, h, e, p);
  } while (mpz_cmp_ui (g, 1));

  mpz_clear (p_3);
  mpz_clear (e);
  mpz_clear (h);
}

/* Still incomplete */
const char *
eg_paramgen_new (size_t nbits)
{
  mpz_t p, q, g, t;
  u_int i;
  char *res = NULL;
  /* buffer use within gen_p */
  char *raw_p; 
  u_int raw_psize = (DIV_ROUNDUP (nbits >> 3, sha1_hashsize)) * sha1_hashsize;

  /* initialize the seed used to generate randomness for p, q and g */
  u_int seedsize = DIV_ROUNDUP (sha1_hashsize, 8) + 1; 
  u_int64_t *seed = (u_int64_t *) malloc (seedsize * sizeof (u_int64_t));
  if (!seed)  
    return NULL;

  raw_p = (char *) malloc (raw_psize * sizeof (char));
  if (!raw_p) {
    free (seed);
    return NULL;
  }
    
  for (i = 0; i < seedsize; i++)
    seed[i] = prng_gethyper ();

  mpz_init (p);
  mpz_init (q);
  mpz_init (g);
  mpz_init (t);

  do {
    gen_q (q, seed, seedsize);
    /* this is for schnorr params, where p = k * q + 1, for some k */
    gen_p (p, raw_p, q, nbits, seed, seedsize);

  } while (!mpz_probab_prime_p (p, PRIMETEST_ITER) || 
	   !mpz_probab_prime_p (q, PRIMETEST_ITER));

  /* now find a generator */
  gen_g (g, p, q, seed, seedsize);

  /* done with these buffers */
  free (raw_p);
  free (seed);

  /* prepare the output */
  if (cat_str (&res, "p=")
      || cat_mpz (&res, p)
      || cat_str (&res, ",q=")
      || cat_mpz (&res, q)
      || cat_str (&res, ",g=")
      || cat_mpz (&res, g)) {
    free (res);
    res = NULL;
  }

  mpz_clear (p);
  mpz_clear (q);
  mpz_clear (g);
  mpz_clear (t);

  return res;
}
