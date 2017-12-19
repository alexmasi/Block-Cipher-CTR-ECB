/* $Id:*/

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

#ifndef _DC_CONF_H_
#define _DC_CONF_H_ 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE 1

#include "dc_autoconf.h"

#if defined (HAVE_GMP_CXX_OPS) || !defined (__cplusplus)
#include <gmp.h>
#else /* !HAVE_GMP_CXX_OPS */
/* Some older C++ header files fail to include some declarations
 * inside an extern "C". */
extern "C" {
#include <gmp.h>
}
#endif /* !HAVE_GMP_CXX_OPS */

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#elif defined (HAVE_SYS_TIME_H)
# include <sys/time.h>
#else /* !TIME_WITH_SYS_TIME && !HAVE_SYS_TIME_H */
# include <time.h>
#endif /* !TIME_WITH_SYS_TIME && !HAVE_SYS_TIME_H */

#ifdef HAVE_TIMES
# include <sys/times.h>
#endif /* HAVE_TIMES */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <unistd.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif /* HAVE_SYS_FILE_H */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if STDC_HEADERS
# include <string.h>
# ifndef bzero
#  define bzero(a,b)   memset((a), 0, (b))
# endif /* !bzero */
#else /* !STDC_HEADERS */
# ifndef DMALLOC
#  ifndef HAVE_STRCHR
#   define strchr index
#   define strrchr rindex
#  endif /* !HAVE_STRCHR */
#  ifdef __cplusplus
char *strchr (const char *, int);
char *strrchr (const char *, int);
#  else /* !__cplusplus */
char *strchr ();
char *strrchr ();
#  endif /* !__cplusplus */
#  ifdef HAVE_MEMCPY
#   define bzero(a,b)   memset((a), 0, (b))
#  else /* !HAVE_MEMCPY */
#   define memcpy(d, s, n) bcopy ((s), (d), (n))
#   define memmove(d, s, n) bcopy ((s), (d), (n))
#  endif /* !HAVE_MEMCPY */
# endif /* !DMALLOC */
#endif

#ifndef HAVE_ISXDIGIT
#define isxdigit(d) (((d) == '0')||((d) == '1')||((d) == '2')||((d) == '3') \
		    ((d) == '4')||((d) == '5')||((d) == '6')||((d) == '7') \
		    ((d) == '8')||((d) == '9')||((d) == 'a')||((d) == 'b') \
		    ((d) == 'c')||((d) == 'd')||((d) == 'e')||((d) == 'f') \
		    ((d) == 'A')||((d) == 'B')||((d) == 'C')||((d) == 'D') \
		    ((d) == 'E')||((d) == 'F'))
#endif /* !HAVE_ISXDIGIT */

#ifdef DMALLOC

# define CHECK_BOUNDS 1

# define DMALLOC_FUNC_CHECK
# ifdef HAVE_MEMORY_H
#  include <memory.h>
# endif /* HAVE_MEMORY_H */
# include <dmalloc.h>

# undef memcpy
#undef xfree
#undef xstrdup

#if DMALLOC_VERSION_MAJOR < 5  || \
     (DMALLOC_VERSION_MAJOR == 5 && DMALLOC_VERSION_MINOR < 5)

# define memcpy(to, from, len) \
   _dmalloc_memcpy((char *) (to), (const char *) (from), len)
# define memmove(to, from, len) \
   _dmalloc_bcopy((const char *) (from), (char *) (to), len)
#define xstrdup(__s) ((char *) dmalloc_strdup(__FILE__, __LINE__, __s, 1))

#else /* version >= 5.5 */


#define xstrdup(__s) \
((char *) dmalloc_strndup(__FILE__, __LINE__, __s, (-1), 0))

#endif /* version <=> 5.5 */

/* Work around Dmalloc's misunderstanding of free's definition */
# if DMALLOC_VERSION_MAJOR >= 5
#  define _xmalloc_leap(f, l, s) \
    dmalloc_malloc (f, l, s, DMALLOC_FUNC_MALLOC, 0, 1)
#  define _malloc_leap(f, l, s) \
    dmalloc_malloc (f, l, s, DMALLOC_FUNC_MALLOC, 0, 0)
#  define _xfree_leap(f, l, p) dmalloc_free (f, l, p, DMALLOC_FUNC_FREE)

# endif /* DMALLOC_VERSION_MAJOR >= 5 */

static inline void
_xfree_wrap (const char *file, int line, void *ptr)
{
  if (ptr)
    _xfree_leap(file, line, ptr);
}
static inline void
xfree (void *ptr)
{
  if (ptr)
    _xfree_leap("unknown file", 0, ptr);
}
#define xfree(ptr) _xfree_wrap(__FILE__, __LINE__, ptr)

const char *stktrace (const char *file);
extern int stktrace_record;
#define txmalloc(size) _xmalloc_leap (stktrace (__FILE__), __LINE__, size)
  
#endif /* !DMALLOC */

#ifndef xstrdup
# define xstrdup(s) strcpy (xmalloc (strlen (s) + 1), (s))
#endif /* !xstrdup */

/* xmalloc and xrealloc are #ifdef'd in dcmisc.c */
#ifndef xmalloc
void *xmalloc(size_t n);
#endif /* !xmalloc */

#ifndef xrealloc
void *xrealloc(void *p, size_t n);
#endif /* !xrealloc */

#ifndef xfree
# define xfree free
#endif /* !xfree */

/*
 * Compiler/arhcitecture attributes
 */

#if __GNUC__ < 2 
# ifndef __attribute__
#  define __attribute__(x)
# endif /* !__attribute__ */
#endif /* !gcc 2 */

#ifndef HAVE_SSIZE_T
typedef int ssize_t;
#endif /* !HAVE_SSIZE_T */
#ifndef HAVE_INT32_T
typedef int int32_t;
#endif /* !HAVE_INT32_T */
#ifndef HAVE_U_INT32_T
typedef unsigned int u_int32_t;
#endif /* !HAVE_U_INT32_T */
#ifndef HAVE_U_INT16_T
typedef unsigned short u_int16_t;
#endif /* !HAVE_U_INT16_T */
#ifndef HAVE_U_INT8_T
typedef unsigned char u_int8_t;
#endif /* !HAVE_U_INT8_T */
#ifndef HAVE_MODE_T
typedef unsigned short mode_t;
#endif /* !HAVE_MODE_T */
#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
#endif /* !HAVE_U_CHAR */
#ifndef HAVE_U_INT
typedef unsigned int u_int;
#endif /* !HAVE_U_INT */
#ifndef HAVE_U_LONG
typedef unsigned long u_long;
#endif /* !HAVE_U_LONG */

#ifndef HAVE_INT64_T
# if SIZEOF_LONG == 8
typedef long int64_t;
# elif SIZEOF_LONG_LONG == 8
typedef long long int64_t;
# else /* Can't find 64-bit type */
#  error "Cannot find any 64-bit data types"
# endif /* !SIZEOF_LONG_LONG */
#endif /* !HAVE_INT64_T */

#ifndef HAVE_U_INT64_T
# if SIZEOF_LONG == 8
typedef unsigned long u_int64_t;
# elif SIZEOF_LONG_LONG == 8
typedef unsigned long long u_int64_t;
# else /* Can't find 64-bit type */
#  error "Cannot find any 64-bit data types"
# endif /* !SIZEOF_LONG_LONG */
# define HAVE_U_INT64_T 1	/* XXX */
#endif /* !HAVE_INT64_T */

#if SIZEOF_LONG == 8
# define INT64(n) n##L
# define U64F "l"
#elif SIZEOF_LONG_LONG == 8
# define INT64(n) n##LL
# if defined (__sun__) && defined (__svr4__)
#  define U64F "ll"
# else /* everyone else */
#  define U64F "q"
# endif /* everyone else */
#else /* Can't find 64-bit type */
# error "Cannot find any 64-bit data types"
#endif /* !SIZEOF_LONG_LONG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_DC_CONF_H_ */
