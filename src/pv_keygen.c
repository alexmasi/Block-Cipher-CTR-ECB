#include "pv.h"

void
write_skfile (const char *skfname, void *raw_sk, size_t raw_sklen)
{
  int fdsk = 0;
  char *s = NULL;
  int status = 0;

  /* armor the raw symmetric key in raw_sk using armor64 */
  s = armor64(raw_sk, raw_sklen);

  /* now write the armored symmetric key to skfname */
  if ((fdsk = open(skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror(getprogname());
    free(s);

    /* scrub the buffer that's holding the key before exiting */
    char* raw_sk_char = (char*)raw_sk;
    for (size_t i = 0; i < raw_sklen; ++i)
      raw_sk_char[i] = 0;

    exit (-1);
  } else {
    status = write(fdsk, s, strlen(s));
    if (status != -1) {
      status = write(fdsk, "\n", 1);
    }
    free(s);
    close(fdsk);
    /* do not scrub the key buffer under normal circumstances
       (it's up to the caller) */

    if (status == -1) {
      printf("%s: trouble writing symmetric key to file %s\n", getprogname (), skfname);
      perror(getprogname ());

    /* scrub the buffer that's holding the key before exiting */
    char* raw_sk_char = (char*)raw_sk;
    for (size_t i = 0; i < raw_sklen; ++i)
      raw_sk_char[i] = 0;
    exit (-1);
    }
  }
}

void
usage (const char *pname)
{
  printf("Personal Vault: Symmetric Key Generation\n");
  printf("Usage: %s SK-FILE \n", pname);
  printf("       Generates a new symmetric key, and writes it to\n");
  printf("       SK-FILE.  Overwrites previous file content, if any.\n");
  exit(1);
}

int
main (int argc, char **argv)
{
  char keys[2 * CCA_STRENGTH]; /* CCA_STRENGTH defined in pv.h */

  if (argc != 2) {
    usage(argv[0]);
  } else {
    setprogname(argv[0]);

    /* first, create a new symmetric key */
    ri();
    prng_getbytes(keys, 2 * CCA_STRENGTH);

    /* now armor and dump to disk the symmetric key buffer */
    write_skfile(argv[1], keys, 2 * CCA_STRENGTH);

    /* finally, scrub the buffers that held the random bits
       by overwriting with a bunch of 0's */
    for (int i = 0; i < 2 * CCA_STRENGTH; ++i)
      keys[i] = 0;
  }
  return 0;
}
