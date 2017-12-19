#include <assert.h>

#include <stdio.h>
#include "dcrypt.h"

/* try to read file block by block */ 
#define BUFSIZE 512 

/* try to read len bytes from fd into buf 
   returns -1 on error; otherwise, the number of bytes actually read into 
   buf is returned.  A return value different from -1 and len indicates EOF 
*/ 
int 
read_chunk (int fd, char *buf, u_int len) 
{
  int cur_bytes_read = 0;
  u_int bytes_read = 0;

  do {
    bytes_read += cur_bytes_read;
    cur_bytes_read = read (fd, buf, len - bytes_read);
  } while (cur_bytes_read > 0);

  return ((cur_bytes_read == -1) ? -1 : (int) bytes_read);
}

char
hex_nibble (u_char _nib) 
{
  u_char nib = (_nib & 0x0f);

  return ((nib < 10) ? ('0' + nib) : ('a' + nib - 10));
}

char *
sha1_digest (int fin, const char *pname, const char *fname)
{
  int bytes_read;
  u_int i, j; 
  char *buf = (char *) malloc (BUFSIZE * sizeof (char));
  char *dig = (char *) malloc (sha1_hashsize * sizeof (char));
  char *res = (char *) malloc ((2 * sha1_hashsize + 1) * sizeof (char));
  sha1_ctx sc;  /* will hold the incremental hash */

  sha1_init (&sc);

  do 
    switch (bytes_read = read_chunk (fin, buf, BUFSIZE)) {
    case -1:
      printf ("%s: trouble reading from %s\n", pname, fname);
      
      exit (-1);
    case 0:
      break;
    case BUFSIZE:
      sha1_update (&sc, buf, BUFSIZE);
      continue;
    default:
      sha1_update (&sc, buf, bytes_read);
      sha1_final (&sc, (u_char *) dig);
      break;
    } 
  while (bytes_read == BUFSIZE);

  for (i = j = 0; i < sha1_hashsize; i++) {
    res[j++] = hex_nibble ((dig[i] & 0xf0) >> 4);
    res[j++] = hex_nibble (dig[i] & 0x0f);
  }
  res[j] = '\0';
  free (buf);
  free (dig);

  return res;
}

void 
usage (const char *pname)
{
  printf ("Simple SHA1 Hash Oracle\n");
  printf ("Usage: %s [FILE]\n", pname);
  printf ("       Without arguments, prints to standard output the SHA1 hash of its own binaries.\n");
  printf ("       With an argument, checks if FILE exists: if so hashes the content of FILE and\n");
  printf("        writes the resulting digest to standard output.\n");
  exit (1);
}

int 
main (int argc, char **argv)
{
  int fd;
  char *digest;

  switch (argc) {
  case 1:
    /* if called without arguments, hashes its own binaries */ 
    argv[1] = argv[0];
    /* purposedly fall over to next case... */
  case 2:
    /* Check if argv[1] is an existing files */
    if ((fd = open (argv[1], O_RDONLY)) == -1) {
      if (errno == ENOENT) {
	usage (argv[0]);
      }
      else {
	perror (argv[0]);
      
	exit (-1);
      }
    }

    digest = sha1_digest (fd, argv[0], argv[1]);
    close (fd);
    
    printf ("SHA1 (%s) = %s\n", argv[1], digest);
    free (digest); /* allocated in sha1_digest */

    break;
  default:
    usage (argv[0]);
  }  

  return 0;
}

