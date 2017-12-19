## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.13 2005/01/10 23:38:11 nicolosi Exp $

lib_LIBRARIES = libdcrypt.a
LIBDCRYPT = $(top_builddir)/libdcrypt.a
TESTS = tst tst_sha1

#LIBGMP = /usr/local/lib/libgmp.a

noinst_PROGRAMS = $(TESTS)

noinst_HEADERS = dcinternal.h
include_HEADERS = dcrypt.h dc_conf.h dc_autoconf.h

BUILT_SOURCES = dc_autoconf.h

libdcrypt_a_SOURCES = dcconf.c dcmisc.c dcops.c mpz_raw.c \
	pad.c prime.c armor.c mdblock.c sha1.c aes.c \
	sha1oracle.c prng.c elgamal.c rabin.c

dcconf.o : dc_autoconf.h

tst_SOURCES = tst.c 
tst_LDADD = $(LIBDCRYPT) $(LIBGMP)
tst_sha1_SOURCES = tst_sha1.c
tst_sha1_LDADD = $(LIBDCRYPT) $(LIBGMP)

dc_autoconf.h: stamp-auto-h
        @:

stamp-auto-h: $(srcdir)/dc_autoconf.sed $(CONFIG_HEADER)
	@rm -f dc_autoconf.h~
	sed -f $(srcdir)/dc_autoconf.sed $(CONFIG_HEADER) > dc_autoconf.h~
	cmp dc_autoconf.h~ dc_autoconf.h || mv -f dc_autoconf.h~ dc_autoconf.h
	@rm -f dc_autoconf.h~
	@echo timestamp > stamp-auto-h

# this gets called when we make dist
# basically we want setup to be in the tarball (just for reference)
# but we want it not executable so that the user doesn't run it
# by mistake
dist-hook:
	cd $(distdir) && rm -f dc_autoconf.h
	cd $(distdir) && chmod -x setup

EXTRA_DIST = setup dc_autoconf.sed

CLEANFILES = core *.core *~

MAINTAINERCLEANFILES = aclocal.m4 install-sh mkinstalldirs \
	missing configure config.guess config.sub config.h.in \
	ltconfig ltmain.sh INSTALL COPYING Makefile.in stamp-h.in
