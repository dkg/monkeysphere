/* Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net> */
/* Date: Fri, 04 Apr 2008 19:31:16 -0400 */
/* License: GPL v3 or later */

#include "gnutls-helpers.h"

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



int init_gnutls() {
  const char* version = NULL;
  const char* debug_string = NULL;
  int ret;

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
  return 0;
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
