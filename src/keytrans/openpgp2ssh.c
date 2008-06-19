#include "gnutls-helpers.h"

#include <gnutls/openpgp.h>
#include <gnutls/x509.h>

/* for waitpid() */
#include <sys/types.h>
#include <sys/wait.h>

/* 
   Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
   Date: 2008-06-12 13:47:41-0400
   License: GPL v3 or later

   monkeysphere key translator: execute this with an OpenPGP key on
   stdin, (please indicate the specific keyid that you want as the
   first argument if there are subkeys).  At the moment, only public
   keys and passphraseless secret keys work.

   For secret keys, it will spit out a PEM-encoded version of the key
   on stdout, which can be fed into ssh-add like this:

    gpg --export-secret-keys $KEYID | openpgp2ssh $KEYID | ssh-add -c /dev/stdin

   For public keys, it will spit out a single line of text that can
   (with some massaging) be used in an openssh known_hosts or
   authorized_keys file.  For example:

    echo server.example.org $(gpg --export $KEYID | openpgp2ssh $KEYID) >> ~/.ssh/known_hosts

   Requirements: I've only built this so far with GnuTLS v2.3.x.
   GnuTLS 2.2.x does not contain the appropriate functionality.

 */


/* FIXME: keyid should be const as well */
int convert_private_pgp_to_x509(gnutls_x509_privkey_t* output, const gnutls_openpgp_privkey_t* pgp_privkey, gnutls_openpgp_keyid_t* keyid) {
  gnutls_datum_t m, e, d, p, q, u, g, y, x;
  gnutls_pk_algorithm_t pgp_algo;
  unsigned int pgp_bits;
  int ret;
  gnutls_openpgp_keyid_t curkeyid;
  int subkeyidx;
  int subkeycount;
  int found = 0;

  init_datum(&m);
  init_datum(&e);
  init_datum(&d);
  init_datum(&p);
  init_datum(&q);
  init_datum(&u);
  init_datum(&g);
  init_datum(&y);
  init_datum(&x);

  subkeycount = gnutls_openpgp_privkey_get_subkey_count(*pgp_privkey);
  if (subkeycount < 0) {
    err(0,"Could not determine subkey count (got value %d)\n", subkeycount);
    return 1;
  }

  if ((keyid == NULL) && 
      (subkeycount > 0)) {
    err(0,"No keyid passed in, but there were %d keys to choose from\n", subkeycount + 1);
    return 1;
  }

  if (keyid != NULL) {
    ret = gnutls_openpgp_privkey_get_key_id(*pgp_privkey, curkeyid);
    if (ret) {
      err(0,"Could not get keyid (error: %d)\n", ret);
      return 1;
    }
  }
  if ((keyid == NULL) || (memcmp(*keyid, curkeyid, sizeof(gnutls_openpgp_keyid_t)) == 0)) {
    /* we want to export the primary key: */
    err(0,"exporting primary key\n");

    /* FIXME: this is almost identical to the block below for subkeys.
       This clumsiness seems inherent in the gnutls OpenPGP API,
       though.  ugh. */
    pgp_algo = gnutls_openpgp_privkey_get_pk_algorithm(*pgp_privkey, &pgp_bits);
    if (pgp_algo < 0) {
      err(0, "failed to get OpenPGP key algorithm (error: %d)\n", pgp_algo);
      return 1;
    }
    if (pgp_algo == GNUTLS_PK_RSA) {
      err(0,"OpenPGP RSA Key, with %d bits\n", pgp_bits);
      ret = gnutls_openpgp_privkey_export_rsa_raw(*pgp_privkey, &m, &e, &d, &p, &q, &u);
      if (GNUTLS_E_SUCCESS != ret) {
	err(0, "failed to export RSA key parameters (error: %d)\n", ret);
	return 1;
      }
      
    } else if (pgp_algo == GNUTLS_PK_DSA) {
      err(0,"OpenPGP DSA Key, with %d bits\n", pgp_bits);
      ret = gnutls_openpgp_privkey_export_dsa_raw(*pgp_privkey, &p, &q, &g, &y, &x);
      if (GNUTLS_E_SUCCESS != ret) {
	err(0,"failed to export DSA key parameters (error: %d)\n", ret);
	return 1;
      }
    }
    found = 1;
  } else {
    /* lets trawl through the subkeys until we find the one we want: */
    for (subkeyidx = 0; (subkeyidx < subkeycount) && !found; subkeyidx++) {
      ret = gnutls_openpgp_privkey_get_subkey_id(*pgp_privkey, subkeyidx, curkeyid);
      if (ret) {
	err(0,"Could not get keyid of subkey with index %d (error: %d)\n", subkeyidx, ret);
	return 1;
      }
      if (memcmp(*keyid, curkeyid, sizeof(gnutls_openpgp_keyid_t)) == 0) {
	err(0,"exporting subkey index %d\n", subkeyidx);

	/* FIXME: this is almost identical to the block above for the
	   primary key. */
	pgp_algo = gnutls_openpgp_privkey_get_subkey_pk_algorithm(*pgp_privkey, subkeyidx, &pgp_bits);
	if (pgp_algo < 0) {
	  err(0,"failed to get the algorithm of the OpenPGP public key (error: %d)\n", pgp_algo);
	  return pgp_algo;
	} else if (pgp_algo == GNUTLS_PK_RSA) {
	  err(0,"OpenPGP RSA key, with %d bits\n", pgp_bits);
	  ret = gnutls_openpgp_privkey_export_subkey_rsa_raw(*pgp_privkey, subkeyidx, &m, &e, &d, &p, &q, &u);
	  if (GNUTLS_E_SUCCESS != ret) {
	    err(0,"failed to export RSA key parameters (error: %d)\n", ret);
	    return 1;
	  }
	} else if (pgp_algo == GNUTLS_PK_DSA) {
	  err(0,"OpenPGP DSA Key, with %d bits\n", pgp_bits);
	  ret = gnutls_openpgp_privkey_export_subkey_dsa_raw(*pgp_privkey, subkeyidx, &p, &q, &g, &y, &x);
	  if (GNUTLS_E_SUCCESS != ret) {
	    err(0,"failed to export DSA key parameters (error: %d)\n", ret);
	    return 1;
	  }
	}
	found = 1;
      }
    }
  }

  if (!found) {
    err(0,"Could not find key in input\n");
    return 1;
  }

  if (pgp_algo == GNUTLS_PK_RSA) {
    ret = gnutls_x509_privkey_import_rsa_raw (*output, &m, &e, &d, &p, &q, &u); 
    if (GNUTLS_E_SUCCESS != ret) {
      err(0, "failed to import RSA key parameters (error: %d)\n", ret);
      return 1;
    }
  } else if (pgp_algo == GNUTLS_PK_DSA) {
    ret = gnutls_x509_privkey_import_dsa_raw (*output, &p, &q, &g, &y, &x); 
    if (GNUTLS_E_SUCCESS != ret) {
      err(0,"failed to import DSA key parameters (error: %d)\n", ret);
      return 1;
    }
  } else {
    err(0,"OpenPGP Key was not RSA or DSA -- can't deal! (actual algorithm was: %d)\n", pgp_algo);
    return 1;
  }
  
  ret = gnutls_x509_privkey_fix(*output);
  if (ret != 0) {
    err(0,"failed to fix up the private key in X.509 format (error: %d)\n", ret);
    return 1; 
  }

  return 0;
}

/* FIXME: keyid should be const also */
int emit_public_openssh_from_pgp(const gnutls_openpgp_crt_t* pgp_crt, gnutls_openpgp_keyid_t* keyid) {
  gnutls_openpgp_keyid_t curkeyid;
  int ret;
  int subkeyidx;
  int subkeycount;
  int found = 0;
  gnutls_datum_t m, e, p, q, g, y, algolabel;
  unsigned int bits;
  gnutls_pk_algorithm_t algo;
  const gnutls_datum_t* all[5];
  const char* algoname;
  int mpicount;
  /* output_data must be at least 2 chars longer than the maximum possible
     algorithm name: */
  char output_data[20];

  /* variables for the output conversion: */
  int pipestatus;
  int pipefd, child_pid;
  char* const b64args[] = {"/usr/bin/base64", "--wrap=0", NULL};

  init_datum(&m);
  init_datum(&e);
  init_datum(&p);
  init_datum(&q);
  init_datum(&g);
  init_datum(&algolabel);


  /* figure out if we've got the right thing: */
  subkeycount = gnutls_openpgp_crt_get_subkey_count(*pgp_crt);
  if (subkeycount < 0) {
    err(0,"Could not determine subkey count (got value %d)\n", subkeycount);
    return 1;
  }

  if ((keyid == NULL) && 
      (subkeycount > 0)) {
    err(0,"No keyid passed in, but there were %d keys to choose from\n", subkeycount + 1);
    return 1;
  }

  if (keyid != NULL) {
    ret = gnutls_openpgp_crt_get_key_id(*pgp_crt, curkeyid);
    if (ret) {
      err(0,"Could not get keyid (error: %d)\n", ret);
      return 1;
    }
  }
  if ((keyid == NULL) || (memcmp(*keyid, curkeyid, sizeof(gnutls_openpgp_keyid_t)) == 0)) {
    /* we want to export the primary key: */
    err(0,"exporting primary key\n");

    /* FIXME: this is almost identical to the block below for subkeys.
       This clumsiness seems inherent in the gnutls OpenPGP API,
       though.  ugh. */
    algo = gnutls_openpgp_crt_get_pk_algorithm(*pgp_crt, &bits);
    if (algo < 0) {
      err(0,"failed to get the algorithm of the OpenPGP public key (error: %d)\n", algo);
      return algo;
    } else if (algo == GNUTLS_PK_RSA) {
      err(0,"OpenPGP RSA certificate, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_pk_rsa_raw(*pgp_crt, &m, &e);
      if (GNUTLS_E_SUCCESS != ret) {
	err(0,"failed to export RSA certificate parameters (error: %d)\n", ret);
	return 1;
      }
    } else if (algo == GNUTLS_PK_DSA) {
      err(0,"OpenPGP DSA certificate, with %d bits\n", bits);
      ret = gnutls_openpgp_crt_get_pk_dsa_raw(*pgp_crt, &p, &q, &g, &y);
      if (GNUTLS_E_SUCCESS != ret) {
	err(0,"failed to export DSA certificate parameters (error: %d)\n", ret);
	return 1;
      }
    }
    found = 1;

  } else {
    /* lets trawl through the subkeys until we find the one we want: */
    for (subkeyidx = 0; (subkeyidx < subkeycount) && !found; subkeyidx++) {
      ret = gnutls_openpgp_crt_get_subkey_id(*pgp_crt, subkeyidx, curkeyid);
      if (ret) {
	err(0,"Could not get keyid of subkey with index %d (error: %d)\n", subkeyidx, ret);
	return 1;
      }
      if (memcmp(*keyid, curkeyid, sizeof(gnutls_openpgp_keyid_t)) == 0) {
	err(0,"exporting subkey index %d\n", subkeyidx);

	/* FIXME: this is almost identical to the block above for the
	   primary key. */
	algo = gnutls_openpgp_crt_get_subkey_pk_algorithm(*pgp_crt, subkeyidx, &bits);
	if (algo < 0) {
	  err(0,"failed to get the algorithm of the OpenPGP public key (error: %d)\n", algo);
	  return algo;
	} else if (algo == GNUTLS_PK_RSA) {
	  err(0,"OpenPGP RSA certificate, with %d bits\n", bits);
	  ret = gnutls_openpgp_crt_get_subkey_pk_rsa_raw(*pgp_crt, subkeyidx, &m, &e);
	  if (GNUTLS_E_SUCCESS != ret) {
	    err(0,"failed to export RSA certificate parameters (error: %d)\n", ret);
	    return 1;
	  }
	} else if (algo == GNUTLS_PK_DSA) {
	  err(0,"OpenPGP DSA certificate, with %d bits\n", bits);
	  ret = gnutls_openpgp_crt_get_subkey_pk_dsa_raw(*pgp_crt, subkeyidx, &p, &q, &g, &y);
	  if (GNUTLS_E_SUCCESS != ret) {
	    err(0,"failed to export DSA certificate parameters (error: %d)\n", ret);
	    return 1;
	  }
	}
	found = 1;
	
      }
    }
  }

  if (!found) {
    err(0,"Could not find key in input\n");
    return 1;
  }

  /* if we made it this far, we've got MPIs, and we've got the
     algorithm, so we just need to emit the info */
  if (algo == GNUTLS_PK_RSA) {
    algoname = "ssh-rsa";
    mpicount = 3;

    all[0] = &algolabel;
    all[1] = &e;
    all[2] = &m;
  } else if (algo == GNUTLS_PK_DSA) {
    algoname = "ssh-dss";
    mpicount = 5;

    all[0] = &algolabel;
    all[1] = &p;
    all[2] = &q;
    all[3] = &g;
    all[4] = &y;
  } else {
    err(0,"Key algorithm was neither DSA nor RSA (it was %d).  Can't deal.  Sorry!\n", algo);
    return 1;
  }

  if (ret = datum_from_string(&algolabel, algoname), ret) {
    err(0,"couldn't label string (error: %d)\n", ret);
    return ret;
  }

  snprintf(output_data, sizeof(output_data), "%s ", algoname);

  pipefd = create_writing_pipe(&child_pid, b64args[0], b64args);
  if (pipefd < 0) {
    err(0,"failed to create a writing pipe (returned %d)\n", pipefd);
    return pipefd;
  }
    
  write(1, output_data, strlen(output_data));

  if (0 != write_data_fd_with_length(pipefd, all, mpicount)) {
    err(0,"was not able to write out RSA key data\n");
    return 1;
  }
  close(pipefd);
  if (child_pid != waitpid(child_pid, &pipestatus, 0)) {
    err(0,"could not wait for child process to return for some reason.\n");
    return 1;
  }
  if (pipestatus != 0) {
    err(0,"base64 pipe died with return code %d\n", pipestatus);
    return pipestatus;
  }

  write(1, "\n", 1);
  
  return 0;
}

int main(int argc, char* argv[]) {
  gnutls_datum_t data;
  int ret;
  gnutls_x509_privkey_t x509_privkey;
  gnutls_openpgp_privkey_t pgp_privkey;
  gnutls_openpgp_crt_t pgp_crt;

  char output_data[10240];
  size_t ods = sizeof(output_data);
  
  gnutls_openpgp_keyid_t keyid;
  gnutls_openpgp_keyid_t* use_keyid;

  init_gnutls();

  /* figure out what keyid we should be looking for: */
  use_keyid = NULL;
  if (argv[1] != NULL) {
    ret = convert_string_to_keyid(keyid, argv[1]);
    if (ret != 0)
      return ret;
    use_keyid = &keyid;
  }

  
  init_datum(&data);

  /* slurp in the key from stdin */
  if (ret = set_datum_fd(&data, 0), ret) {
    err(0,"didn't read file descriptor 0\n");
    return 1;
  }


  if (ret = gnutls_openpgp_privkey_init(&pgp_privkey), ret) {
    err(0,"Failed to initialized OpenPGP private key (error: %d)\n", ret);
    return 1;
  }
  /* check whether it's a private key or a public key, by trying them: */
  if ((gnutls_openpgp_privkey_import(pgp_privkey, &data, GNUTLS_OPENPGP_FMT_RAW, NULL, 0) == 0) || 
      (gnutls_openpgp_privkey_import(pgp_privkey, &data, GNUTLS_OPENPGP_FMT_BASE64, NULL, 0) == 0)) {
    /* we're dealing with a private key */
    err(0,"Translating private key\n");
    if (ret = gnutls_x509_privkey_init(&x509_privkey), ret) {
      err(0,"Failed to initialize X.509 private key for output (error: %d)\n", ret);
      return 1;
    }
    
    ret = convert_private_pgp_to_x509(&x509_privkey, &pgp_privkey, use_keyid);

    gnutls_openpgp_privkey_deinit(pgp_privkey);
    if (ret)
      return ret;

    ret = gnutls_x509_privkey_export (x509_privkey,
				      GNUTLS_X509_FMT_PEM,
				      output_data,
				      &ods);
    if (ret == 0) {
      write(1, output_data, ods);
    }
    gnutls_x509_privkey_deinit(x509_privkey);
  
  } else {
    if (ret = gnutls_openpgp_crt_init(&pgp_crt), ret) {
      err(0,"Failed to initialized OpenPGP certificate (error: %d)\n", ret);
      return 1;
    }
    
    if ((gnutls_openpgp_crt_import(pgp_crt, &data, GNUTLS_OPENPGP_FMT_RAW) == 0) || 
	(gnutls_openpgp_crt_import(pgp_crt, &data, GNUTLS_OPENPGP_FMT_BASE64) == 0)) {
      /* we're dealing with a public key */
      err(0,"Translating public key\n");

      ret = emit_public_openssh_from_pgp(&pgp_crt, use_keyid);
      
    } else {
      /* we have no idea what kind of key this is at all anyway! */
      err(0,"Input does contain any form of OpenPGP key I recognize.\n");
      return 1;
    }
  }

  gnutls_global_deinit();
  return 0;
}
