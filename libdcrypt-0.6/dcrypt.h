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

#ifndef _DCRYPT_H_
#define _DCRYPT_H_ 1

#include "dc_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct dckey dckey;

/* aes.c */
struct aes_ctx {
  int nrounds;
  u_int32_t  e_key[60];
  u_int32_t  d_key[60];
};
typedef struct aes_ctx aes_ctx;
enum { aes_blocklen = 16 };
void aes_setkey (aes_ctx *aes, const void *key, u_int keylen);
void aes_clrkey (aes_ctx *aes);
void aes_encrypt (const aes_ctx *aes, void *buf, const void *ibuf);
void aes_decrypt (const aes_ctx *aes, void *buf, const void *ibuf);

/* armor.c */
char *armor32 (const void *dp, size_t dl);
ssize_t armor32len (const char *s);
ssize_t dearmor32len (const char *s);
ssize_t dearmor32 (void *out, const char *s);
char *armor64 (const void *dp, size_t len);
ssize_t armor64len (const char *s);
ssize_t dearmor64len (const char *s);
ssize_t dearmor64 (void *out, const char *s);

/* dcmisc.c */
void putint (void *_dp, u_int32_t val);
u_int32_t getint (const void *_dp);
void puthyper (void *_dp, u_int64_t val);
u_int64_t gethyper (const void *_dp);
int cat_str (char **dstp, const char *src);
int cat_mpz (char **dstp, const MP_INT *mp);
int cat_int (char **dstp, int i);
int skip_str (const char **srcp, const char *str);
int read_mpz (const char **srcp, MP_INT *mp);

/* mdblock.c */
struct mdblock {
  u_int64_t count;
  void (*consume) (struct mdblock *, const unsigned char block[64]);
  unsigned char buffer[64];
};
typedef struct mdblock mdblock;

/* sha1.c */
struct sha1_ctx {
  mdblock mdb;
  u_int32_t state[5];
};
typedef struct sha1_ctx sha1_ctx;
enum { sha1_hashsize = 20 };
void sha1_init (sha1_ctx *sc);
void sha1_update (sha1_ctx *sc, const void *bytes, size_t len);
void sha1_final (sha1_ctx *sc, u_char out[20]);
void sha1_hash (void *digest, const void *buf, size_t len);
void hmac_sha1 (const char *key, size_t keylen, 
		void *out, const void *data, size_t dlen);
void hmac_sha1_init (const char *key, size_t keylen, sha1_ctx *sc);
#define hmac_sha1_update(a,b,c)    sha1_update((a),(b),(c))
void hmac_sha1_final (const char *key, size_t keylen, sha1_ctx *sc, 
		      u_char out[20]); 

/* prng.c */
/* WARNING:  The following functions are not thread-safe. */
void prng_getbytes (void *buf, size_t len);
u_int32_t prng_getword (void);
u_int64_t prng_gethyper (void);
void prng_seed (void *buf, size_t len);
/* the following assumes that elem has been initialized already */
void prng_getfrom_zn (mpz_t elem, const mpz_t n);

/* dcops.c */
dckey *dckeygen (const char *type, size_t k, const char *extra);
dckey *dcimport_pub (const char *asc);
dckey *dcimport_priv (const char *asc);
dckey *dckeydup (const dckey *key);
void dcfree (dckey *key);
char *dcexport (const dckey *key);
char *dcexport_pub (const dckey *key);
char *dcexport_priv (const dckey *key);
char *dcencrypt (const dckey *key, const char *msg);
char *dcdecrypt (const dckey *key, const char *msg);
char *dcsign (const dckey *key, const char *msg);
/* returns 0 upon success, -1 if check fails */
int dcverify (const dckey *key, const char *msg, const char *sig);
int dcispriv (const dckey *);
int dcareequiv (const dckey *keya, const dckey *keyb);

/* elgamal.c */
const char *eg_paramgen (size_t nbits);
const char *eg_paramgen_new (size_t nbits);
const char *eg_getparam_default (size_t nbits);
extern const char *(*eg_getparam) (size_t nbits);

#define DC_ELGAMAL "Elgamal-1"
#define DC_RABIN "Rabin-1"

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* !_DCRYPT_H_ */
