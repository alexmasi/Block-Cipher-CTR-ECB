#include "block.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /***************************************************************************
  * Use AES in ECB mode for encryption and AES as a CBC-MAC for auth
  * The overall layout of an encrypted file will be:
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-ECB (plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   ***************************************************************************/

  int ctxt = 0;
  int bytes_read=0;
  int i=0;

  aes_ctx aesEnc, aesMac;

  char ctxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH], mac_buf[CCA_STRENGTH];
  char mac_buf_temp[CCA_STRENGTH];

  char *sk_enc, *sk_mac;
  /* Create the ciphertext file---the content will be encrypted */

  if ((ctxt = open(ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror(getprogname());

    /* scrub the buffer that's holding the key before exiting */

    char* raw_sk_char = (char*)raw_sk;
    for (size_t i = 0; i < raw_len; ++i)
      raw_sk_char[i] = 0;
    exit (-1);
  }

  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/
  sk_enc = raw_sk;
  aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);

  /* ... and the second part for the AES-CBC-MAC */
  sk_mac = raw_sk+CCA_STRENGTH;
  aes_setkey(&aesMac, sk_mac, CCA_STRENGTH);

  /* start CBC-MAC with "IV" of all 0s */
  for(i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = 0;
  }

  while((bytes_read = read(fin, buf, CCA_STRENGTH)) == CCA_STRENGTH) {
    aes_encrypt(&aesEnc, ctxt_buf, buf);
    write(ctxt, ctxt_buf, CCA_STRENGTH);

    /* add to MAC */
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf[i] ^ ctxt_buf[i];
    }
    aes_encrypt(&aesMac, mac_buf_temp, mac_buf);
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf_temp[i];
    }
  }

  /* Don't forget to pad the last block with trailing zeroes */
  for(i=bytes_read; i<CCA_STRENGTH; ++i) {
    buf[i] = 0;
  }

  /* write the last chunk */
  aes_encrypt(&aesEnc, ctxt_buf, buf);
  write(ctxt, ctxt_buf, CCA_STRENGTH);

  /* Finish up computing the AES-CBC-MAC and write the resulting
   * 16-byte MAC after the last chunk of the AES-CTR ciphertext */

  for(i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = mac_buf[i] ^ ctxt_buf[i];
  }
  aes_encrypt(&aesMac, mac_buf_temp, mac_buf);
  for(i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = mac_buf_temp[i];
  }
  write(ctxt, mac_buf, CCA_STRENGTH);
  close(ctxt);
}

void
usage (const char *pname)
{
  printf("Personal Vault: Encryption \n");
  printf("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf("       If CTEXT-FILE existed, any previous content is lost.\n");
  exit(1);
}

int
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;

  if (argc != 4) {
    usage(argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open(argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open(argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage(argv[0]);
    }
    else {
      perror(argv[0]);
      exit(-1);
    }
  }
  else {
    setprogname(argv[0]);

    /* Import symmetric key from argv[1] */
    if (!(import_sk_from_file(&raw_sk, &raw_len, fdsk))) {
      printf("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      close(fdsk);
      exit(2);
    }
    close (fdsk);

    /* Perform Encryption */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);

    /* scrub the buffer that's holding the key before exiting */
    for (size_t i = 0; i < raw_len; ++i)
      raw_sk[i] = 0;
    close (fdptxt);
  }
  return 0;
}
