/* $Id: dcinternal.h,v 1.10 1999/07/16 16:06:03 dm Exp $ */

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

#ifndef _DCINTERNAL_H_
#define _DCINTERNAL_H_ 1

/* Don't wrap dcrypt.h with extern "C"; it includes gmp.h, which needs 
   special care */
#include "dcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

typedef struct pkvtbl pkvtbl;
typedef enum keytype { PUBLIC = 61, PRIVATE = 253 } keytype;

struct dckey {
  pkvtbl *vptr;
  keytype type;
};

struct pkvtbl {
  char *name;

  char *(*encrypt) (const dckey *key, const char *msg);
  int (*verify) (const dckey *key, const char *msg, const char *sig);
  char *(*serialize_pub) (const dckey *key);
  void (*free_pub) (dckey *key);
  dckey *(*import_pub) (const char *asc);

  char *(*decrypt) (const dckey *key, const char *ctext);
  char *(*sign) (const dckey *key, const char *msg);
  char *(*serialize_priv) (const dckey *key);
  void (*free_priv) (dckey *key);
  dckey *(*import_priv) (const char *asc);

  dckey *(*keygen) (size_t k, const char *extra);
};

extern const pkvtbl *dcconf[];

/* mdblock.c */
void mdblock_init (mdblock *mp,
		   void (*consume) (mdblock *, const u_char block[64]));
void mdblock_update (mdblock *mp, const void *bytes, size_t len);
void mdblock_finish (mdblock *mp, int bigendian);

/* sha1.c */
void sha1_newstate (u_int32_t state[5]);
void sha1_transform (u_int32_t state[5], const u_char block[64]);
void sha1_state2bytes (void *_cp, const u_int32_t state[5]);

/* sha1oracle.c */
struct sha1oracle_ctx {
  mdblock mdb;
  int firstblock;
  size_t nbytes;
  size_t nstate;
  u_int32_t (*state)[5];
};
typedef struct sha1oracle_ctx sha1oracle_ctx;
void sha1oracle_init (sha1oracle_ctx *soc, size_t nbytes, u_int64_t idx);
void sha1oracle_update (sha1oracle_ctx *soc, const void *bytes, size_t len);
void sha1oracle_final (sha1oracle_ctx *soc, u_char *out);

/* prime.c */
extern const u_int small_primes[];
extern const int num_small_primes;
void random_bigint (MP_INT *, size_t bits);
void random_zn (MP_INT *, const MP_INT *n);
int primecheck (const MP_INT *n);
int sprimecheck (const MP_INT *n, MP_INT *q);

/* mpz_raw.c */
size_t mpz_sizeinbase2 (const MP_INT *mp);
int mpz_getbit (const MP_INT *mp, size_t bit);
void mpz_get_rawmag_le (char *buf, size_t size, const MP_INT *mp);
void mpz_get_rawmag_be (char *buf, size_t size, const MP_INT *mp);
void mpz_set_rawmag_le (MP_INT *mp, const char *buf, size_t size);
void mpz_set_rawmag_be (MP_INT *mp, const char *buf, size_t size);

/* pad.c */
void sha1oracle_lookup (int idx, char *dst, size_t dstlen,
			const char *src, size_t srclen);
int pre_encrypt (MP_INT *out, const char *msg, size_t nbits);
char *post_decrypt (const MP_INT *m, size_t nbits);
int pre_sign (MP_INT *out, sha1_ctx *sc, size_t nbits);
int post_verify (sha1_ctx *sc, const MP_INT *s, size_t nbits);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_DCINTERNAL_H_ */
