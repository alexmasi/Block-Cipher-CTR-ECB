# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/
DCRYPTINCLUDE = ../libdcrypt-0.6/
DCRYPTLIB = ../libdcrypt-0.6/
DMALLOC = #-ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# The source file(s) for each program
all : keygen ctr_encrypt ctr_decrypt ecb_encrypt ecb_decrypt

misc.o : misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c misc.c

keygen.o : keygen.c misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c keygen.c misc.c

ctr_encrypt.o : ctr_encrypt.c misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c ctr_encrypt.c misc.c

ctr_decrypt.o : ctr_decrypt.c misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c ctr_decrypt.c misc.c

ecb_encrypt.o : ecb_encrypt.c misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c ecb_encrypt.c misc.c

ecb_decrypt.o : ecb_decrypt.c misc.c block.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c ecb_decrypt.c misc.c

keygen : keygen.o misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

ctr_encrypt : ctr_encrypt.o misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

ctr_decrypt : ctr_decrypt.o misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

ecb_encrypt : ecb_encrypt.o misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

ecb_decrypt : ecb_decrypt.o misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)


clean :
	-rm -f keygen ctr_encrypt ctr_decrypt ecb_encrypt ecb_decrypt core *.core *.o *~

.PHONY : all clean
