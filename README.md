# Block-Cipher-CTR-ECB
An AES implementation of a CTR block cipher using a CBC-MAC along with an ECB implementation for comparison.

## Getting started
In the `libdcrypt` directory, run 
```
$ ./configure
```
After successful configuration build the executables by running
```
$ make
``` 
Now the AES Pseudo Random Permutation is avaliable for use in the `src` executables. Finally in `src` run
```
$ make
```

## Usage
In the `src` directory, run 
```
$ ./keygen keyfile
``` 
to generate a 64-bit key saved to `keyfile`. To encrypt, run 
```
$ ./ctr_encrypt keyfile plaintext ciphertext
```
to encrypt the content of `plaintext` to a file named `ciphertext`. To decrypt, run
```
$ ./ctr_decrypt keyfile ciphertext plaintext
```
to decrypt the content of `ciphertext` to a file named `plaintext`. 

Likewise use `ecb` instead of `ctr` to encrypt using the Electronic Code Book (ECB) mode of operation for the AES block cipher instead of the Counter (CTR) mode of operation. Note that the CTR mode is Chosen Plaintext Attack (CPA) secure while the ECB mode is not. Also the CTR mode implementation includes a Cipher Block Chaining Message Authentication Code (CBC-MAC) along with the standard encryption to upgrade the scheme from CPA secure to Chosen Ciphertext Attack (CCA) secure making the `ctr` suite secure against man-in-the-middle tampering to the ciphertext. Thus the `ctr` suite is more secure and desirable than the `ecb` suite.

## Examples
In the `examples` directory there are bitmap images encrypted with both `ctr` mode and `ecb` mode to show how inferior `ecb` is when encrypting files. Notice that the circles.bmp image is still very clear with `ecb` due to no randomization of state tracking in the mode making the encryption not CPA secure. The `ctr` mode is CPA secure and CCA secure (due to the CBC-MAC) making the bmp image encryption appear much more "random".

## Authors
* **Alex Masi**
* **Walter Krawec**

## Acknowledgments

* Thank you:
  * Professor Walter Krawec
  * Libdcrypt
* Originally created for an Honor's Conversion in CSE 4702: Intro to Modern Cryptography at the University of Connecticut taught by Professor Walter Krawec.

