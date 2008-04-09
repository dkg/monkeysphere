#include "gnutls-helpers.h"

#include <gnutls/openpgp.h>
#include <gnutls/x509.h>

/* for htonl() */
#include <arpa/inet.h>


/* 
   Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
   Date: Tue, 08 Apr 2008
   License: GPL v3 or later

   monkeysphere public key translator: execute this with an GPG
   certificate (public key(s) + userid(s)) on stdin.  It currently
   only works with RSA keys.

   It will spit out a version of the first key capable of being used
   for authentication on stdout.  The output format should be suitable
   for appending a known_hosts file.

   Requirements: I've only built this so far with GnuTLS v2.3.4 --
   version 2.2.0 does not contain the appropriate pieces.

 */

int main(int argc, char* argv[]) {
  gnutls_datum_t data;
  int ret;
  gnutls_openpgp_crt_t openpgp_crt;
  gnutls_openpgp_keyid_t keyid;
  printable_keyid p_keyid;
  unsigned int keyidx;
  unsigned int usage, bits;
  gnutls_pk_algorithm_t algo;

  gnutls_datum_t m, e, p, q, g, y;

  char output_data[10240];
  size_t ods = sizeof(output_data);

  init_gnutls();
  
  init_datum(&data);

  init_datum(&m);
  init_datum(&e);
  init_datum(&p);
  init_datum(&q);
  init_datum(&g);
  init_datum(&y);

  init_keyid(keyid);

  /* slurp in the private key from stdin */
  if (ret = set_datum_fd(&data, 0), ret) {
    err("didn't read file descriptor 0\n");
    return 1;
  }


  if (ret = gnutls_openpgp_crt_init(&openpgp_crt), ret) {
    err("Failed to initialize OpenPGP certificate (error: %d)\n", ret);
    return 1;
  }

  /* format could be either: GNUTLS_OPENPGP_FMT_RAW,
     GNUTLS_OPENPGP_FMT_BASE64; if MONKEYSPHERE_RAW is set, use RAW,
     otherwise, use BASE64: */

  if (getenv("MONKEYSPHERE_RAW")) {
    err("assuming RAW formatted certificate\n");
    if (ret = gnutls_openpgp_crt_import(openpgp_crt, &data, GNUTLS_OPENPGP_FMT_RAW), ret) {
      err("failed to import the OpenPGP certificate in RAW format (error: %d)\n", ret);
      return ret;
    }
  } else {
    err("assuming BASE64 formatted certificate\n");
    if (ret = gnutls_openpgp_crt_import (openpgp_crt, &data, GNUTLS_OPENPGP_FMT_BASE64), ret) {
      err("failed to import the OpenPGP certificate in BASE64 format (error: %d)\n", ret);
      return ret;
    }
  }

  if (gnutls_openpgp_crt_get_revoked_status(openpgp_crt)) {
    err("the primary key was revoked!\n");
    return 1;
  }

  if (ret = gnutls_openpgp_crt_get_key_usage(openpgp_crt, &usage), ret) {
    err("failed to get the usage flags for the primary key (error: %d)\n", ret);
    return ret;
  }
  if (usage & GNUTLS_KEY_KEY_AGREEMENT) {
    err("the primary key can be used for authentication\n");

    algo = gnutls_openpgp_crt_get_pk_algorithm(openpgp_crt, &bits);
    if (algo < 0) {
      err("failed to get the algorithm of the OpenPGP public key (error: %d)\n", algo);
      return algo;
    } else if (algo == GNUTLS_PK_RSA) {
      
      err("OpenPGP RSA certificate, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_pk_rsa_raw(openpgp_crt, &m, &e);
      if (GNUTLS_E_SUCCESS != ret) {
	err ("failed to export RSA key parameters (error: %d)\n", ret);
	return 1;
      }
    } else if (algo == GNUTLS_PK_DSA) {
      err("OpenPGP DSA Key, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_pk_dsa_raw(openpgp_crt, &p, &q, &g, &y);
      if (GNUTLS_E_SUCCESS != ret) {
	err ("failed to export DSA key parameters (error: %d)\n", ret);
	return 1;
      }
    } else {
      err("OpenPGP Key was not RSA or DSA -- can't deal! (actual algorithm was: %d)\n", algo);
      return 1;
    }
    
  } else {
    err("primary key is only good for: 0x%08x.  Trying subkeys...\n", usage);
    
    if (ret = gnutls_openpgp_crt_get_auth_subkey(openpgp_crt, keyid), ret) {
      err("failed to find a subkey capable of authentication (error: %d)\n", ret);
      return ret;
    }
    make_keyid_printable(p_keyid, keyid);
    err("found authentication subkey %.16s\n", p_keyid);

    ret = gnutls_openpgp_crt_get_subkey_idx(openpgp_crt, keyid);
    if (ret < 0) {
      err("could not get the index of subkey %.16s (error: %d)\n", ret);
      return ret;
    }
    keyidx = ret;

    if (gnutls_openpgp_crt_get_subkey_revoked_status(openpgp_crt, keyidx)) {
      err("The authentication subkey was revoked!\n");
      return 1;
    }

    if (ret = gnutls_openpgp_crt_get_subkey_usage(openpgp_crt, keyidx, &usage), ret) {
      err("could not figure out usage of subkey %.16s (error: %d)\n", p_keyid, ret);
      return ret;
    }
    if ((usage & GNUTLS_KEY_KEY_AGREEMENT) == 0) {
      err("could not find a subkey with authentication privileges.\n");
      return 1;
    }

    /* switch, based on the algorithm in question, to extract the MPI
       components: */

    algo = gnutls_openpgp_crt_get_subkey_pk_algorithm(openpgp_crt, keyidx, &bits);
    if (algo < 0) {
      err("failed to get the algorithm of the authentication subkey (error: %d)\n", algo);
      return algo;
    } else if (algo == GNUTLS_PK_RSA) {
      
      err("OpenPGP RSA subkey, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_subkey_pk_rsa_raw(openpgp_crt, keyidx, &m, &e);
      if (GNUTLS_E_SUCCESS != ret) {
	err ("failed to export RSA subkey parameters (error: %d)\n", ret);
	return 1;
      }
    } else if (algo == GNUTLS_PK_DSA) {
      err("OpenPGP DSA subkey, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_subkey_pk_dsa_raw(openpgp_crt, keyidx, &p, &q, &g, &y);
      if (GNUTLS_E_SUCCESS != ret) {
	err ("failed to export DSA subkey parameters (error: %d)\n", ret);
	return 1;
      }
    } else {
      err("OpenPGP subkey was not RSA or DSA -- can't deal! (actual algorithm was: %d)\n", algo);
      return 1;
    }
  } 

  /* now we have algo, and the various MPI data set.  Can we export
     them cleanly? */

  

  gnutls_openpgp_crt_deinit(openpgp_crt);
  gnutls_global_deinit();
  return 0;
}
