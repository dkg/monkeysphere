/* Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net> */
/* Date: Fri, 04 Apr 2008 19:31:16 -0400 */
/* License: GPL v3 or later */


#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>
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

void err(int level, const char* fmt, ...);
void logfunc(int level, const char* string);

/* basic datum manipulations: */

void init_datum(gnutls_datum_t* d);
void copy_datum(gnutls_datum_t* dest, const gnutls_datum_t* src);
int compare_data(const gnutls_datum_t* a, const gnutls_datum_t* b);
void free_datum(gnutls_datum_t* d);
int write_datum_fd(int fd, const gnutls_datum_t* d);
int write_datum_fd_with_length(int fd, const gnutls_datum_t* d);
int write_data_fd_with_length(int fd, const gnutls_datum_t** d, unsigned int num);

/* set up a datum from a null-terminated string */
int datum_from_string(gnutls_datum_t* d, const char* str);

/* keyid manipulations: */
typedef unsigned char printable_keyid[16];

void init_keyid(gnutls_openpgp_keyid_t keyid);
void make_keyid_printable(printable_keyid out, gnutls_openpgp_keyid_t keyid);
void collapse_printable_keyid(gnutls_openpgp_keyid_t out, printable_keyid in);
int convert_string_to_keyid(gnutls_openpgp_keyid_t out, const char* str);
int convert_string_to_printable_keyid(printable_keyid out, const char* str);


/* functions to get data into datum objects: */

/* read the passed-in string, store in a single datum */
int set_datum_string(gnutls_datum_t* d, const char* s);

/* read the passed-in file descriptor until EOF, store in a single
   datum */
int set_datum_fd(gnutls_datum_t* d, int fd);

/* read the file indicated (by name) in the fname parameter.  store
   its entire contents in a single datum. */
int set_datum_file(gnutls_datum_t* d, const char* fname);

/* set up file descriptor pipe for writing (child process pid gets
   stored in pid, fd is returned)*/
int create_writing_pipe(pid_t* pid, const char* path, char* const argv[]);

/* return 0 if userid matches the monkeysphere spec for ssh host user IDs */
int validate_ssh_host_userid(const char* userid);

/* how many bytes will it take to write out this datum in OpenPGP MPI form? */
size_t get_openpgp_mpi_size(gnutls_datum_t* d);

/* write the MPI stored in gnutls_datum_t to file descriptor fd: */
int write_openpgp_mpi_to_fd(int fd, gnutls_datum_t* d);
