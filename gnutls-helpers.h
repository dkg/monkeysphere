/* Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net> */
/* Date: Fri, 04 Apr 2008 19:31:16 -0400 */
/* License: GPL v3 or later */


#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

/* Functions to help dealing with GnuTLS for monkeysphere key
   translation projects: */

/* set everything up, including logging levels.  Return 0 on
   success */
int init_gnutls();

/* logging and output functions: */

void err(const char* fmt, ...);
void logfunc(int level, const char* string);

/* basic datum manipulations: */

void init_datum(gnutls_datum_t* d);
void copy_datum(gnutls_datum_t* dest, const gnutls_datum_t* src);
int compare_data(const gnutls_datum_t* a, const gnutls_datum_t* b);
void free_datum(gnutls_datum_t* d);

/* functions to get data into datum objects: */

/* read the passed-in string, store in a single datum */
int set_datum_string(gnutls_datum_t* d, const char* s);

/* read the passed-in file descriptor until EOF, store in a single
   datum */
int set_datum_fd(gnutls_datum_t* d, int fd);

/* read the file indicated (by na1me) in the fname parameter.  store
   its entire contents in a single datum. */
int set_datum_file(gnutls_datum_t* d, const char* fname);
