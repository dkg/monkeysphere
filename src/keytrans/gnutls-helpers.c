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

/* for exit() */
#include <unistd.h>

#include <assert.h>

/* higher levels allow more frivolous error messages through. 
   this is set with the MONKEYSPHERE_DEBUG variable */
static int loglevel = 0;

void err(int level, const char* fmt, ...) {
  va_list ap;
  if (level > loglevel)
    return;
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
  assert(sizeof(out) >= 2*sizeof(keyid));
  hex_print_data((char*)out, (const char*)keyid, sizeof(keyid));
}

/* you must have twice as many bytes in the out buffer as in the in buffer */
void hex_print_data(char* out, const char* in, size_t incount)
{
  static const char hex[16] = "0123456789ABCDEF";
  unsigned int inix = 0, outix = 0;
  
  while (inix < incount) {
    out[outix] = hex[(in[inix] >> 4) & 0x0f];
    out[outix + 1] = hex[in[inix] & 0x0f];
    inix++;
    outix += 2;
  }
}

unsigned char hex2bin(unsigned char x) {
  if ((x >= '0') && (x <= '9')) 
    return x - '0';
  if ((x >= 'A') && (x <= 'F')) 
    return 10 + x - 'A';
  if ((x >= 'a') && (x <= 'f')) 
    return 10 + x - 'a';
  return 0xff;
}

void collapse_printable_keyid(gnutls_openpgp_keyid_t out, printable_keyid in) {
  unsigned int pkix = 0, outkix = 0;
  
  while (pkix < sizeof(printable_keyid)) {
    unsigned hi = hex2bin(in[pkix]);
    unsigned lo = hex2bin(in[pkix + 1]);
    if (hi == 0xff) {
      err(0, "character '%c' is not a hex char\n", in[pkix]);
      exit(1);
    }
    if (lo == 0xff) {
      err(0, "character '%c' is not a hex char\n", in[pkix + 1]);
      exit(1);
    }
    out[outkix] = lo | (hi << 4);

    pkix += 2;
    outkix++;
  }
}

int convert_string_to_keyid(gnutls_openpgp_keyid_t out, const char* str) {
  printable_keyid p;
  int ret;

  ret = convert_string_to_printable_keyid(p, str);
  if (ret == 0) 
    collapse_printable_keyid(out, p);
  return ret;
}
int convert_string_to_printable_keyid(printable_keyid pkeyid, const char* str) {
  int arglen, x;
  arglen = 0;
  x = 0;
  while ((arglen <= sizeof(printable_keyid)) &&
	 (str[x] != '\0')) {
    if (isxdigit(str[x])) {
      if (arglen == sizeof(printable_keyid)) {
	err(0, "There are more than %d hex digits in the keyid '%s'\n", sizeof(printable_keyid), str);
	return 1;
      }
      pkeyid[arglen] = str[x];
      arglen++;
    }
    x++;
  }
  
  if (arglen != sizeof(printable_keyid)) {
    err(0, "Keyid '%s' is not %d hex digits in length\n", str, sizeof(printable_keyid));
    return 1;
  }
  return 0;
}



int init_gnutls() {
  const char* version = NULL;
  const char* debug_string = NULL;
  int ret;

  if (debug_string = getenv("MONKEYSPHERE_DEBUG"), debug_string) {
    loglevel = atoi(debug_string);
  }

  if (ret = gnutls_global_init(), ret) {
    err(0, "Failed to do gnutls_global_init() (error: %d)\n", ret);
    return 1;
  }

  version = gnutls_check_version(NULL);

  if (version) 
    err(1, "gnutls version: %s\n", version);
  else {
    err(0, "no gnutls version found!\n");
    return 1;
  }

  gnutls_global_set_log_function(logfunc);
  
  gnutls_global_set_log_level(loglevel);
  err(1, "set log level to %d\n", loglevel);

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
    err(0,"a is larger\n");
    return 1;
  }
  if (a->size < b->size) {
    err(0,"b is larger\n");
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
      err(0,"out of memory!\n");
      return -1;
    }
    d->size = bufsize;
  } else {
    bufsize = d->size;
  }
  f = fdopen(fd, "r");
  if (NULL == f) {
    err(0,"could not fdopen FD %d\n", fd);
  }
  clearerr(f);
  while (!feof(f) && !ferror(f)) { 
    if (len == bufsize) {
      /* allocate more space by doubling: */
      bufsize *= 2;
      d->data = gnutls_realloc(d->data, bufsize);
      if (d->data == NULL) {
	err(0,"out of memory!\n"); 
	return -1;
      };
      d->size = bufsize;
    }
    len += fread(d->data + len, 1, bufsize - len, f);
    /*     err(0,"read %d bytes\n", len); */
  }
  if (ferror(f)) {
    err(0,"Error reading from fd %d (error: %d) (error: %d '%s')\n", fd, ferror(f), errno, strerror(errno));
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
    err(0,"failed to stat '%s'\n", fname);
    return -1;
  }
  
  c = gnutls_realloc(d->data, sbuf.st_size);
  if (NULL == c) {
    err(0,"failed to allocate %d bytes for '%s'\n", sbuf.st_size, fname);
    return -1;
  }

  d->data = c;
  d->size = sbuf.st_size;
  file = fopen(fname, "r");
  if (NULL == file) {
    err(0,"failed to open '%s' for reading\n",  fname);
    return -1;
  }

  x = fread(d->data, d->size, 1, file);
  if (x != 1) {
    err(0,"tried to read %d bytes, read %d instead from '%s'\n", d->size, x, fname);
    fclose(file);
    return -1;
  }
  fclose(file);
  return 0;
}

int write_datum_fd(int fd, const gnutls_datum_t* d) {
  if (d->size != write(fd, d->data, d->size)) {
    err(0,"failed to write body of datum.\n");
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
    err(0,"failed to write size of datum.\n");
    return -2;
  }
  if (looks_negative) {
    if (write(fd, &zero, 1) != 1) {
      err(0,"failed to write padding byte for MPI.\n");
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
    err(0,"bad pointer passed to create_writing_pipe()\n");
    return -1;
  }

  if (ret = pipe(p), ret == -1) {
    err(0,"failed to create a pipe (error: %d \"%s\")\n", errno, strerror(errno));
    return -1;
  }

  *pid = fork();
  if (*pid == -1) {
    err(0,"Failed to fork (error: %d \"%s\")\n", errno, strerror(errno));
    return -1;
  }
  if (*pid == 0) { /* this is the child */
    close(p[1]); /* close unused write end */
    
    if (0 != dup2(p[0], 0)) { /* map the reading end into stdin */
      err(0,"Failed to transfer reading file descriptor to stdin (error: %d \"%s\")\n", errno, strerror(errno));
      exit(1);
    }
    execv(path, argv);
    err(0,"exec %s failed (error: %d \"%s\")\n", path, errno, strerror(errno));
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
    err(0,"The user ID should start with ssh:// for a host key\n");
    goto fail;
  }
  /* so that isalnum will work properly */
  userid += strlen("ssh://");
  while (0 != (*userid)) {
    if (!isalnum(*userid)) {
      err(0,"label did not start with a letter or a digit! (%s)\n", userid);
      goto fail;
    }
    userid++;
    while (isalnum(*userid) || ('-' == (*userid)))
      userid++;
    if (('.' == (*userid)) || (0 == (*userid))) { /* clean end of label:
						 check last char
						 isalnum */
      if (!isalnum(*(userid - 1))) {
	err(0,"label did not end with a letter or a digit!\n");
	goto fail;
      }
      if ('.' == (*userid)) /* advance to the start of the next label */
	userid++;
    } else {
      err(0,"invalid character in domain name: %c\n", *userid);
      goto fail;
    }
  }
  /* ensure that the last character is valid: */
  if (!isalnum(*(userid - 1))) {
    err(0,"hostname did not end with a letter or a digit!\n");
    goto fail;
  }
  /* FIXME: fqdn's can be unicode now, thanks to RFC 3490 -- how do we
     make sure that we've got an OK string? */

  return 0;

 fail:
  setlocale(LC_ALL, oldlocale);
  return 1;
}

/* http://tools.ietf.org/html/rfc4880#section-5.5.2 */
size_t get_openpgp_mpi_size(gnutls_datum_t* d) {
  return 2 + d->size;
}

int write_openpgp_mpi_to_fd(int fd, gnutls_datum_t* d) {
  uint16_t x;

  x = d->size * 8;
  x = htons(x);
  
  write(fd, &x, sizeof(x));
  write(fd, d->data, d->size);
  
  return 0;
}
