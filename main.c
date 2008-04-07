#include "gnutls-helpers.h"

#include <gnutls/openpgp.h>
#include <gnutls/x509.h>

/* 
   Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
   Date: Tue, 01 Apr 2008
   License: GPL v3 or later

   monkeysphere private key translator: execute this with an GPG
   secret key on stdin (at the moment, only passphraseless RSA keys
   work).

   It will spit out a PEM-encoded version of the key on stdout, which
   can be fed into ssh-add like this:

    gpg --export-secret-keys $KEYID | monkeysphere | ssh-add -c /dev/stdin

   Requirements: I've only built this so far with GnuTLS v2.3.4 --
   version 2.2.0 does not contain the appropriate pieces.

   Notes: gpgkey2ssh doesn't seem to provide the same public
   keys. Mighty weird!

0 wt215@squeak:~/monkeysphere$ gpg --export-secret-keys 1DCDF89F | ~dkg/src/monkeysphere/monkeysphere  | ssh-add -c /dev/stdin
gnutls version: 2.3.4
OpenPGP RSA Key, with 1024 bits
Identity added: /dev/stdin (/dev/stdin)
The user has to confirm each use of the key
0 wt215@squeak:~/monkeysphere$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC9gWQqfrnhQKDQnND/3eOexpddE64J+1zp9fcyCje7H5LKclb6DBV2HS6WgW32PJhIzvP+fYZM3dzXea3fpv14y1SicXiRBDgF9SnsNA1qWn2RyzkLcKy7PmM0PDYtU1oiLTcQj/xkWcqW2sLKHT/WW+vZP5XP7RMGN/yWNMfE2Q== /dev/stdin
0 wt215@squeak:~/monkeysphere$ gpgkey2ssh 1DCDF89F
ssh-rsa AAAAB3NzaC1yc2EAAACBAL2BZCp+ueFAoNCc0P/d457Gl10Trgn7XOn19zIKN7sfkspyVvoMFXYdLpaBbfY8mEjO8/59hkzd3Nd5rd+m/XjLVKJxeJEEOAX1Kew0DWpafZHLOQtwrLs+YzQ8Ni1TWiItNxCP/GRZypbawsodP9Zb69k/lc/tEwY3/JY0x8TZAAAAAwEAAQ== COMMENT
0 wt215@squeak:~/monkeysphere$ 

 */



int main(int argc, char* argv[]) {
  gnutls_x509_privkey_t x509_privkey;
  gnutls_datum_t data, test, clean;
  int ret;

  /*  
      const char *certfile, *keyfile;
      gnutls_certificate_credentials_t pgp_creds;
  */
  gnutls_datum_t m, e, d, p, q, u, g, y, x;

  /*  gnutls_x509_crt_t crt; */

  gnutls_openpgp_privkey_t pgp_privkey;
  gnutls_pk_algorithm_t pgp_algo;
  unsigned int pgp_bits;

  char output_data[10240];
  size_t ods = sizeof(output_data);

  init_gnutls();
  
  init_datum(&data);
  init_datum(&test);
  init_datum(&clean);
  init_datum(&m);
  init_datum(&e);
  init_datum(&d);
  init_datum(&p);
  init_datum(&q);
  init_datum(&u);
  init_datum(&g);
  init_datum(&y);
  init_datum(&x);


  if (ret = gnutls_x509_privkey_init(&x509_privkey), ret) {
    err("Failed to initialize X.509 private key (error: %d)\n", ret);
    return 1;
  }

  if (ret = gnutls_openpgp_privkey_init(&pgp_privkey), ret) {
    err("Failed to initialized OpenPGP private key (error: %d)\n", ret);
    return 1;
  }

  /* slurp in the private key from stdin */
  if (ret = set_datum_fd(&data, 0), ret) {
    err("didn't read file descriptor 0\n");
    return 1;
  }

  /* Or, instead, read in key from a file name: 
  if (ret = set_datum_file(&data, argv[1]), ret) {
    err("didn't read file '%s'\n", argv[1]);
    return 1;
  }
*/

  /* treat the passed file as an X.509 private key, and extract its
     component values: */

/*   if (ret = gnutls_x509_privkey_import(x509_privkey, &data, GNUTLS_X509_FMT_PEM), ret) { */
/*     err("Failed to import the X.509 key (error: %d)\n", ret); */
/*     return 1; */
/*   } */
/*   gnutls_x509_privkey_export_rsa_raw(x509_privkey, &m, &e, &d, &p, &q, &u); */

  /* try to print the PEM-encoded private key: */
/*   ret = gnutls_x509_privkey_export (x509_privkey, */
/* 				    GNUTLS_X509_FMT_PEM, */
/* 				    output_data, */
/* 				    &ods); */
/*   printf("ret: %u; ods: %u;\n", ret, ods); */
/*   if (ret == 0) { */
/*     write(0, output_data, ods); */
/*   } */

  /* format could be either: GNUTLS_OPENPGP_FMT_RAW,
     GNUTLS_OPENPGP_FMT_BASE64; if MONKEYSPHERE_RAW is set, use RAW,
     otherwise, use BASE64: */

  if (getenv("MONKEYSPHERE_RAW")) {
    err("assuming RAW formatted private keys\n");
    if (ret = gnutls_openpgp_privkey_import(pgp_privkey, &data, GNUTLS_OPENPGP_FMT_RAW, NULL, 0), ret)
      err("failed to import the OpenPGP private key in RAW format (error: %d)\n", ret);
  } else {
    err("assuming BASE64 formatted private keys\n");
    if (ret = gnutls_openpgp_privkey_import (pgp_privkey, &data, GNUTLS_OPENPGP_FMT_BASE64, NULL, 0), ret)
      err("failed to import the OpenPGP private key in BASE64 format (error: %d)\n", ret);
  }

  pgp_algo = gnutls_openpgp_privkey_get_pk_algorithm(pgp_privkey, &pgp_bits);
  if (pgp_algo < 0) {
    err("failed to get OpenPGP key algorithm (error: %d)\n", pgp_algo);
    return 1;
  }
  if (pgp_algo == GNUTLS_PK_RSA) {
    err("OpenPGP RSA Key, with %d bits\n", pgp_bits);
    ret = gnutls_openpgp_privkey_export_rsa_raw(pgp_privkey, &m, &e, &d, &p, &q, &u);
    if (GNUTLS_E_SUCCESS != ret) {
      err ("failed to export RSA key parameters (error: %d)\n", ret);
      return 1;
    }

    ret = gnutls_x509_privkey_import_rsa_raw (x509_privkey, &m, &e, &d, &p, &q, &u); 
    if (GNUTLS_E_SUCCESS != ret) {
      err ("failed to import RSA key parameters (error: %d)\n", ret);
      return 1;
    }
  } else if (pgp_algo == GNUTLS_PK_DSA) {
    err("OpenPGP DSA Key, with %d bits\n", pgp_bits);
    ret = gnutls_openpgp_privkey_export_dsa_raw(pgp_privkey, &p, &q, &g, &y, &x);
    if (GNUTLS_E_SUCCESS != ret) {
      err ("failed to export DSA key parameters (error: %d)\n", ret);
      return 1;
    }

    ret = gnutls_x509_privkey_import_dsa_raw (x509_privkey, &p, &q, &g, &y, &x); 
    if (GNUTLS_E_SUCCESS != ret) {
      err ("failed to import DSA key parameters (error: %d)\n", ret);
      return 1;
    }
  } else {
    err("OpenPGP Key was not RSA or DSA -- can't deal! (actual algorithm was: %d)\n", pgp_algo);
    return 1;
  }
  
  ret = gnutls_x509_privkey_fix(x509_privkey);
  if (ret != 0) {
    err("failed to fix up the private key in X.509 format (error: %d)\n", ret);
    return 1; 
  }
  ret = gnutls_x509_privkey_export (x509_privkey,
				    GNUTLS_X509_FMT_PEM,
				    output_data,
				    &ods);
  printf("ret: %u; ods: %u;\n", ret, ods);
  if (ret == 0) {
    write(1, output_data, ods);
  }


  gnutls_x509_privkey_deinit(x509_privkey);
  gnutls_openpgp_privkey_deinit(pgp_privkey);
  gnutls_global_deinit();
  return 0;
}
