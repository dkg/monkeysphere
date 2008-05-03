#include "gnutls-helpers.h"

#include <gnutls/openpgp.h>
#include <gnutls/x509.h>

/* for waitpid() */
#include <sys/types.h>
#include <sys/wait.h>

/* for time() */
#include <time.h>

/* for htons() */
#include <arpa/inet.h>


/* 
   Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
   Date: Sun, 2008-04-20
   License: GPL v3 or later

   monkeysphere public key translator: execute this with an ssh
   private key on stdin.  It currently only works with RSA keys.

   it should eventually work with OpenSSH-style public keys instead of
   the full private key, but it was easier to do this way.

   It shoud spit out a version of the public key suitable for acting
   as an OpenPGP public sub key packet.

 */

int main(int argc, char* argv[]) {
  gnutls_datum_t data;
  int ret;
  gnutls_x509_privkey_t x509_privkey;
  gnutls_openpgp_crt_t openpgp_crt;
  gnutls_openpgp_keyid_t keyid;
  printable_keyid p_keyid;
  unsigned int keyidx;
  unsigned int usage, bits;
  gnutls_pk_algorithm_t algo;

  unsigned char packettag;
  unsigned char openpgpversion;
  time_t timestamp;
  uint32_t clunkytime;
  unsigned char openpgpalgo;
  unsigned int packetlen;
  uint16_t plen;

  gnutls_datum_t m, e, d, p, q, u, g, y;
  gnutls_datum_t algolabel;

  char output_data[10240];
  char userid[10240];
  size_t uidsz = sizeof(userid);

  const gnutls_datum_t* all[5];
  int pipefd;
  pid_t child_pid;
  char* const args[] = {"/usr/bin/base64", "--wrap=0", NULL};
  const char* algoname;
  int mpicount;
  int pipestatus;

  init_gnutls();
  
  init_datum(&data);

  init_datum(&m);
  init_datum(&e);
  init_datum(&d);
  init_datum(&p);
  init_datum(&q);
  init_datum(&u);
  init_datum(&g);
  init_datum(&y);

  init_datum(&algolabel);

  init_keyid(keyid);

  /* slurp in the private key from stdin */
  if (ret = set_datum_fd(&data, 0), ret) {
    err("didn't read file descriptor 0\n");
    return 1;
  }


  if (ret = gnutls_x509_privkey_init(&x509_privkey), ret) {
    err("Failed to initialize private key structure (error: %d)\n", ret);
    return 1;
  }

  err("assuming PEM formatted private key\n");
  if (ret = gnutls_x509_privkey_import(x509_privkey, &data, GNUTLS_X509_FMT_PEM), ret) {
    err("failed to import the PEM-encoded private key (error: %d)\n", ret);
    return ret;
  }

  algo = gnutls_x509_privkey_get_pk_algorithm(x509_privkey);
  if (algo < 0) {
    err("failed to get the algorithm of the PEM-encoded public key (error: %d)\n", algo);
    return algo;
  } else if (algo == GNUTLS_PK_RSA) {
    err("RSA private key\n");
    ret = gnutls_x509_privkey_export_rsa_raw(x509_privkey, &m, &e, &d, &p, &q, &u);
    if (GNUTLS_E_SUCCESS != ret) {
      err ("failed to export RSA key parameters (error: %d)\n", ret);
      return 1;
    }
    err("Modulus size %d, exponent size %d\n", m.size, e.size);
  } else if (algo == GNUTLS_PK_DSA) {
    err("DSA Key, not implemented!!\n", bits);
    return 1;
  } else {
    err("Key was not RSA or DSA -- can't deal! (actual algorithm was: %d)\n", algo);
    return 1;
  }

  /* now we have algo, and the various MPI data are set.  Can we
     export them as a public subkey packet? */

  /* this packet should be tagged 14, and should contain:

     1 octet: version (4)
     4 octets: time of generation (seconds since 1970)
     1 octet: algo (http://tools.ietf.org/html/rfc4880#section-5.5.2 implies 1 for RSA)
 
     MPI: modulus
     MPI: exponent
  */

  packetlen = 1 + 4 + 1;
  /* FIXME: this is RSA only.  for DSA, there'll be more: */
  packetlen += get_openpgp_mpi_size(&m) + get_openpgp_mpi_size(&e);

  /* FIXME: we should generate this bound more cleanly -- i just
     happen to know that 65535 is 2^16-1: */
  if (packetlen > 65535) {
    err("packet length is too long (%d)\n", packetlen);
    return 1;
  }

  /* we're going to emit an old-style packet, with tag 14 (public
     subkey), with a two-octet packet length */
  packettag = 0x80 | (14 << 2) | 1;
  
  write(1, &packettag, sizeof(packettag));
  plen = htons(packetlen);
  write(1, &plen, sizeof(plen));

  openpgpversion = 4;
  write(1, &openpgpversion, 1);

  timestamp = time(NULL);
  clunkytime = htonl(timestamp);
  write(1, &clunkytime, 4);

  /* FIXME: handle things other than RSA */
  openpgpalgo = 1;
  write(1, &openpgpalgo, 1);
  
  write_openpgp_mpi_to_fd(1, &m);
  write_openpgp_mpi_to_fd(1, &e);

  gnutls_x509_privkey_deinit(x509_privkey);
  gnutls_global_deinit();
  return 0;
}
