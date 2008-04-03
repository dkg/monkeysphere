#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

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


int loglevel = 0;


void err(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

void logfunc(int level, const char* string) {
  fprintf(stderr, "GnuTLS Logging (%d): %s\n", level, string);
}

void init_datum(gnutls_datum_t* d) {
  d->data = NULL;
  d->size = 0;
}
void copy_datum(gnutls_datum_t* dest, const gnutls_datum_t* src) {
  dest->data = gnutls_realloc(dest->data, src->size);
  dest->size = src->size;
  memcpy(dest->data, src->data, src->size);
}
int compare_data(const gnutls_datum_t* a, const gnutls_datum_t* b) {
  if (a->size > b->size) {
    err("a is larger\n");
    return 1;
  }
  if (a->size < b->size) {
    err("b is larger\n");
    return -1;
  }
  return memcmp(a->data, b->data, a->size);
}
void free_datum(gnutls_datum_t* d) {
  gnutls_free(d->data);
  d->data = NULL;
  d->size = 0;
}

/* read the passed-in string, store in a single datum */
int set_datum_string(gnutls_datum_t* d, const char* s) {
  unsigned int x = strlen(s)+1;
  unsigned char* c = NULL;

  c = gnutls_realloc(d->data, x);
  if (NULL == c)
    return -1;
  d->data = c;
  d->size = x;
  memcpy(d->data, s, x);
  return 0;
}

/* read the passed-in file descriptor until EOF, store in a single
   datum */
int set_datum_fd(gnutls_datum_t* d, int fd) {
  unsigned int bufsize = 1024;
  unsigned int len = 0;

  FILE* f = fdopen(fd, "r");
  if (bufsize > d->size) {
    bufsize = 1024;
    d->data = gnutls_realloc(d->data, bufsize);
    if (d->data == NULL) {
      err("out of memory!\n");
      return -1;
    }
    d->size = bufsize;
  } else {
    bufsize = d->size;
  }
  f = fdopen(fd, "r");
  if (NULL == f) {
    err("could not fdopen FD %d\n", fd);
  }
  clearerr(f);
  while (!feof(f) && !ferror(f)) { 
    if (len == bufsize) {
      /* allocate more space by doubling: */
      bufsize *= 2;
      d->data = gnutls_realloc(d->data, bufsize);
      if (d->data == NULL) {
	err("out of memory!\n"); 
	return -1;
      };
      d->size = bufsize;
    }
    len += fread(d->data + len, 1, bufsize - len, f);
    /*     err("read %d bytes\n", len); */
  }
  if (ferror(f)) {
    err("Error reading from fd %d (error: %d) (error: %d '%s')\n", fd, ferror(f), errno, strerror(errno));
    return -1;
  }
    
  /* touch up buffer size to match reality: */
  d->data = gnutls_realloc(d->data, len);
  d->size = len;
  return 0;
}

/* read the file indicated (by na1me) in the fname parameter.  store
   its entire contents in a single datum. */
int set_datum_file(gnutls_datum_t* d, const char* fname) {
  struct stat sbuf;
  unsigned char* c = NULL;
  FILE* file = NULL;
  size_t x = 0;

  if (0 != stat(fname, &sbuf)) {
    err("failed to stat '%s'\n", fname);
    return -1;
  }
  
  c = gnutls_realloc(d->data, sbuf.st_size);
  if (NULL == c) {
    err("failed to allocate %d bytes for '%s'\n", sbuf.st_size, fname);
    return -1;
  }

  d->data = c;
  d->size = sbuf.st_size;
  file = fopen(fname, "r");
  if (NULL == file) {
    err("failed to open '%s' for reading\n",  fname);
    return -1;
  }

  x = fread(d->data, d->size, 1, file);
  if (x != 1) {
    err("tried to read %d bytes, read %d instead from '%s'\n", d->size, x, fname);
    fclose(file);
    return -1;
  }
  fclose(file);
  return 0;
}


int main(int argc, char* argv[]) {
  const char* version = NULL;
  const char* debug_string = NULL;

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

  if (ret = gnutls_global_init(), ret) {
    err("Failed to do gnutls_global_init() (error: %d)\n", ret);
    return 1;
  }



  version = gnutls_check_version(NULL);

  if (version) 
    err("gnutls version: %s\n", version);
  else {
    err("no version found!\n");
    return 1;
  }

  if (debug_string = getenv("MONKEYSPHERE_DEBUG"), debug_string) {
    loglevel = atoi(debug_string);
    gnutls_global_set_log_function(logfunc);
    
    gnutls_global_set_log_level(loglevel);
    err("set log level to %d\n", loglevel);
  }

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

  copy_datum(&clean, &data);
  copy_datum(&test, &data);
  
  if (0 != compare_data(&data, &clean)) 
    err("data do not match after initial copy\n");
  /* format could be either: GNUTLS_OPENPGP_FMT_RAW,
     GNUTLS_OPENPGP_FMT_BASE64; we'll try them both, raw first */



/*   if (ret = gnutls_openpgp_privkey_import(pgp_privkey, &data, GNUTLS_OPENPGP_FMT_RAW, NULL, 0), ret) */
/*     err("failed to import the OpenPGP private key in RAW format (error: %d)\n", ret); */
/*   if (0 != compare_data(&data, &clean))  */
/*     err("Datum changed after privkey  import in raw format!\n"); */


  if (ret = gnutls_openpgp_privkey_import (pgp_privkey, &data, GNUTLS_OPENPGP_FMT_BASE64, NULL, 0), ret)
    err("failed to import the OpenPGP private key in BASE64 format (error: %d)\n", ret);
  if (0 != compare_data(&data, &clean))
    err("Datum changed after privkey  import in base64 format!\n");



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
  
  /* const gnutls_datum_t * m, const gnutls_datum_t * e, const gnutls_datum_t * d, const gnutls_datum_t * p, const gnutls_datum_t * q, const gnutls_datum_t * u); */
  
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
