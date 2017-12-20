#include "block.h"

void
decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin, int file_size)
{
  /***************************************************************************
   * Use AES in ECB mode for decryption and AES as a CBC-MAC to verify the tag
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-CTR (plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   */

  int ptxt = 0;
  int bytes_read = 0;
  int bytes_total_read = 0;
  int num_blocks = 0;

  aes_ctx aesEnc, aesMac;

  char ptxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH], mac_buf[CCA_STRENGTH];
  char mac_buf_temp[CCA_STRENGTH];

  char *sk_enc, *sk_mac;
  int i = 0, j = 0;

  /* use the first part of the symmetric key for the AES-CTR decryption ...*/
  /* ... and the second for the AES-CBC-MAC */
  if ((ptxt = open(ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror(getprogname());

    /* scrub the buffer that's holding the key before exiting */
    char* raw_sk_char = (char*)raw_sk;
    for (size_t i = 0; i < raw_len; ++i)
      raw_sk_char[i] = 0;
    exit (-1);
  }

  /* get file size in bytes:*/
  printf("File size: %i\n", file_size);

  /* First part for the AES-CTR */
  sk_enc = raw_sk;
  aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);

  /* ... and the second part for the AES-CBC-MAC */
  sk_mac = raw_sk+CCA_STRENGTH;
  aes_setkey(&aesMac, sk_mac, CCA_STRENGTH);

  num_blocks = file_size / CCA_STRENGTH-2;
  bytes_total_read = CCA_STRENGTH;

  /* SETUP CBC-MAC */
  for (i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = 0;
  }

  for (j=0; j<num_blocks; ++j) {
    bytes_read = read(fin, buf, CCA_STRENGTH);
    if (bytes_read != CCA_STRENGTH) {
      /* Error: shut down everything - scrub buffers*/
      char* raw_sk_char = (char*)raw_sk;
      for (size_t i = 0; i < raw_len; ++i)
        raw_sk_char[i] = 0;
      for (int i = 0; i < CCA_STRENGTH; ++i)
        ptxt_buf[i] = 0;
        buf[i] = 0;
      exit(-1);
    }

    aes_decrypt(&aesEnc, ptxt_buf, buf);
    write(ptxt, ptxt_buf, CCA_STRENGTH);
    bytes_total_read += CCA_STRENGTH;

    /* COMPUTE CBC-MAC AS YOU GO */
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf[i] ^ buf[i];
    }
    aes_encrypt(&aesMac, mac_buf_temp, mac_buf);
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf_temp[i];
    }
  }

  close(ptxt);
  close(fin);
}

void
usage (const char *pname)
{
  printf("Simple File Decryption Utility\n");
  printf("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf("       Otherwise, tries to use sk to decrypt the content of\n");
  printf("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf("       in PTEXT-FILE; if a decryption problem is encountered\n");
  printf("       after the processing started, PTEXT-FILE is truncated\n");
  printf("       to zero-length and its previous content is lost.\n");
  exit(1);
}

int
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;
  int file_size=0;

  FILE* f = 0;
  if(argc != 4) {
    usage(argv[0]);
  }
  /* get file size of ctxt */
  f = fopen(argv[2], "r");
  fseek(f, 0, SEEK_END);
  file_size = ftell(f);
  fclose(f);

  if (argc != 4) {
    usage(argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open(argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open(argv[2], O_RDONLY)) == -1)) {
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
    if (!(sk = import_sk_from_file(&sk, &sk_len, fdsk))) {
      printf("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      close(fdsk);
      exit(2);
    }
    close(fdsk);

    /* Perform Decryption */
    decrypt_file(argv[3], sk, sk_len, fdctxt, file_size);

    /* scrub the buffer that's holding the key before exiting */
    for (size_t i = 0; i < sk_len; ++i)
      sk[i] = 0;
    close(fdctxt);
  }
  return 0;
}
