#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

void err(const char* fmt, ...) {
  static FILE* STDERR = NULL;
  va_list ap;

  if (NULL == STDERR)
    STDERR = fdopen(STDERR_FILENO, "a");
  va_start(ap, fmt);
  vfprintf(STDERR, fmt, ap);
  va_end(ap);
}


void init_datum(gnutls_datum_t* d) {
  d->data = NULL;
  d->size = 0;
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

  FILE* f = NULL;
  if (bufsize > d->size) {
    bufsize = 1024;
    if (gnutls_realloc(d->data, bufsize) == NULL) {
      err("out of memory!\n");
      return -1;
    }
    d->size = bufsize;
  } else {
    bufsize = d->size;
  }
  f = fdopen(fd, "r");
  while (!feof(f) && !ferror(f)) {
    if (len == bufsize) {
      /* allocate more space by doubling: */
      bufsize *= 2;
      if (gnutls_realloc(d->data, bufsize) == NULL) {
	err("out of memory!\n"); 
	return -1;
      };
      d->size = bufsize;
    }
    len += fread(d->data + len, 1, bufsize - len, f);
  }
  if (ferror(f)) {
    err("Error reading from fd %d\n", fd);
    return -1;
  }
  /* touch up buffer size to match reality: */
  gnutls_realloc(d->data, len);
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

  gnutls_x509_privkey_t x509_privkey;
  gnutls_datum_t data;
  int ret;

  /*  
      const char *certfile, *keyfile;
      gnutls_certificate_credentials_t pgp_creds;
  */
  gnutls_datum_t m, e, d, p, q, u;
  gnutls_x509_crt_t crt;

  gnutls_openpgp_privkey_t pgp_privkey;
  gnutls_openpgp_crt_fmt_t pgp_format;
  gnutls_pk_algorithm_t pgp_algo;
  unsigned int pgp_bits;

  char output_data[10240];
  size_t ods = sizeof(output_data);

  init_datum(&data);

  if (ret = gnutls_global_init(), ret) {
    err("Failed to do gnutls_global_init() (error: %d)\n", ret);
    return 1;
  }



  version = gnutls_check_version(NULL);

  if (version) 
    printf("gnutls version: %s\n", version);
  else {
    printf("no version found!\n");
    return 1;
  }

  if (ret = gnutls_x509_privkey_init(&x509_privkey), ret) {
    err("Failed to initialize X.509 private key (error: %d)\n", ret);
    return 1;
  }

  if (ret = gnutls_openpgp_privkey_init(&pgp_privkey), ret) {
    err("Failed to initialized OpenPGP private key (error: %d)\n", ret);
    return 1;
  }

  /* how do we initialize data? */

    /* reading from the file descriptor doesn't work right yet:
      if (ret = set_datum_fd(&data, 0), ret) {
      err("didn't read file descriptor 0\n");
      return 1;
      }
    */

  if (ret = set_datum_file(&data, argv[1]), ret) {
    err("didn't read file '%s'\n", argv[1]);
    return 1;
  }

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
     GNUTLS_OPENPGP_FMT_BASE64 */
  pgp_format = GNUTLS_OPENPGP_FMT_RAW;
  if (ret = gnutls_openpgp_privkey_import (pgp_privkey, &data, pgp_format, NULL, 0), ret) {
    err("failed to import the OpenPGP private key (error: %d)\n", ret);
    return 1;
  }
  pgp_algo = gnutls_openpgp_privkey_get_pk_algorithm(pgp_privkey, &pgp_bits);
  if (pgp_algo < 0) {
    err("failed to get OpenPGP key algorithm (error: %d)\n", pgp_algo);
    return 1;
  }
  if (pgp_algo != GNUTLS_PK_RSA) {
    err("OpenPGP Key was not RSA (actual algorithm was: %d)\n", pgp_algo);
    return 1;
  }
  
  printf("OpenPGP RSA Key, with %d bits\n", pgp_bits);


  ret = gnutls_x509_privkey_export (pgp_privkey,
				    GNUTLS_X509_FMT_PEM,
				    output_data,
				    &ods);
  printf("ret: %u; ods: %u;\n", ret, ods);
  if (ret == 0) {
    write(0, output_data, ods);
  }


  gnutls_x509_privkey_deinit(x509_privkey);
  gnutls_openpgp_privkey_deinit(pgp_privkey);
  gnutls_global_deinit();
  return 0;
}
