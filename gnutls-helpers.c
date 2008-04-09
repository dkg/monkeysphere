/* Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net> */
/* Date: Fri, 04 Apr 2008 19:31:16 -0400 */
/* License: GPL v3 or later */

#include "gnutls-helpers.h"
/* for htonl() */
#include <arpa/inet.h>

/* for setlocale() */
#include <locale.h>

/* for isalnum() */
#include <ctype.h>

int loglevel = 0;


void err(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fflush(stderr);
}

void logfunc(int level, const char* string) {
  fprintf(stderr, "GnuTLS Logging (%d): %s\n", level, string);
}

void init_keyid(gnutls_openpgp_keyid_t keyid) {
  memset(keyid, 'x', sizeof(gnutls_openpgp_keyid_t));
}



void make_keyid_printable(printable_keyid out, gnutls_openpgp_keyid_t keyid)
{
  static const char hex[16] = "0123456789ABCDEF";
  unsigned int kix = 0, outix = 0;
  
  while (kix < sizeof(gnutls_openpgp_keyid_t)) {
    out[outix] = hex[(keyid[kix] >> 4) & 0x0f];
    out[outix + 1] = hex[keyid[kix] & 0x0f];
    kix++;
    outix += 2;
  }
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

/* read the file indicated (by name) in the fname parameter.  store
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

int write_datum_fd(int fd, const gnutls_datum_t* d) {
  if (d->size != write(fd, d->data, d->size)) {
    err("failed to write body of datum.\n");
    return -1;
  }
  return 0;
}


int write_datum_fd_with_length(int fd, const gnutls_datum_t* d) {
  uint32_t len;
  int looks_negative = (d->data[0] & 0x80);
  unsigned char zero = 0;

  /* if the first bit is 1, then the datum will appear negative in the
     MPI encoding style used by OpenSSH.  In that case, we'll increase
     the length by one, and dump out one more byte */

  if (looks_negative) {
    len = htonl(d->size + 1);
  } else {
    len = htonl(d->size);
  }
  if (write(fd, &len, sizeof(len)) != sizeof(len)) {
    err("failed to write size of datum.\n");
    return -2;
  }
  if (looks_negative) {
    if (write(fd, &zero, 1) != 1) {
      err("failed to write padding byte for MPI.\n");
      return -2;
    }
  }
  return write_datum_fd(fd, d);
}

int write_data_fd_with_length(int fd, const gnutls_datum_t** d, unsigned int num) {
  unsigned int i;
  int ret;

  for (i = 0; i < num; i++)
    if (ret = write_datum_fd_with_length(fd, d[i]), ret != 0)
      return ret;

  return 0;
}


int datum_from_string(gnutls_datum_t* d, const char* str) {
  d->size = strlen(str);
  d->data = gnutls_realloc(d->data, d->size);
  if (d->data == 0)
    return ENOMEM;
  memcpy(d->data, str, d->size);
  return 0;
}


int create_writing_pipe(pid_t* pid, const char* path, char* const argv[]) {
  int p[2];
  int ret;

  if (pid == NULL) {
    err("bad pointer passed to create_writing_pipe()\n");
    return -1;
  }

  if (ret = pipe(p), ret == -1) {
    err("failed to create a pipe (error: %d \"%s\")\n", errno, strerror(errno));
    return -1;
  }

  *pid = fork();
  if (*pid == -1) {
    err("Failed to fork (error: %d \"%s\")\n", errno, strerror(errno));
    return -1;
  }
  if (*pid == 0) { /* this is the child */
    close(p[1]); /* close unused write end */
    
    if (0 != dup2(p[0], 0)) { /* map the reading end into stdin */
      err("Failed to transfer reading file descriptor to stdin (error: %d \"%s\")\n", errno, strerror(errno));
      exit(1);
    }
    execv(path, argv);
    err("exec %s failed (error: %d \"%s\")\n", path, errno, strerror(errno));
    /* close the open file descriptors */
    close(p[0]);
    close(0);

    exit(1);
  } else { /* this is the parent */
    close(p[0]); /* close unused read end */
    return p[1];
  }
}

int validate_ssh_host_userid(const char* userid) {
  char* oldlocale = setlocale(LC_ALL, "C");
  
  /* choke if userid does not match the expected format
     ("ssh://fully.qualified.domain.name") */
  if (strncmp("ssh://", userid, strlen("ssh://")) != 0) {
    err("The user ID should start with ssh:// for a host key\n");
    goto fail;
  }
  /* so that isalnum will work properly */
  userid += strlen("ssh://");
  while (0 != (*userid)) {
    if (!isalnum(*userid)) {
      err("label did not start with a letter or a digit! (%s)\n", userid);
      goto fail;
    }
    userid++;
    while (isalnum(*userid) || ('-' == (*userid)))
      userid++;
    if (('.' == (*userid)) || (0 == (*userid))) { /* clean end of label:
						 check last char
						 isalnum */
      if (!isalnum(*(userid - 1))) {
	err("label did not end with a letter or a digit!\n");
	goto fail;
      }
      if ('.' == (*userid)) /* advance to the start of the next label */
	userid++;
    } else {
      err("invalid character in domain name: %c\n", *userid);
      goto fail;
    }
  }
  /* ensure that the last character is valid: */
  if (!isalnum(*(userid - 1))) {
    err("hostname did not end with a letter or a digit!\n");
    goto fail;
  }
  /* FIXME: fqdn's can be unicode now, thanks to RFC 3490 -- how do we
     make sure that we've got an OK string? */

  return 0;

 fail:
  setlocale(LC_ALL, oldlocale);
  return 1;
}
