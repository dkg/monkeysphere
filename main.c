#define _GNU_SOURCE
#include <stdio.h>
#include <assuan.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <gcrypt.h>
#include <ctype.h>

#define KEYGRIP_LENGTH 40
#define KEYWRAP_ALGO GCRY_CIPHER_AES128
#define KEYWRAP_ALGO_MODE GCRY_CIPHER_MODE_AESWRAP


int custom_log (assuan_context_t ctx, void *hook, unsigned int cat, const char *msg) {
  fprintf (stderr, "assuan (cat %d), %s\n", cat, msg);
  return 1;
}

char* agent_sockname () {
  char *ret = NULL;
  char *ghome = getenv ("GNUPGHOME");
  int rc;
  
  if (ghome != NULL) {
    rc = asprintf (&ret, "%s/S.gpg-agent", ghome);
  } else {
    char *home = getenv ("HOME");
    if (home != NULL) {
      rc = asprintf (&ret, "%s/.gnupg/S.gpg-agent", home);
    } else {
      struct passwd* p = getpwuid(geteuid());
      if (p)
        rc = asprintf (&ret, "%s/.gnupg/S.gpg-agent", p->pw_dir);
      else
        rc = -1;
    }
  }
  if (rc > 0)
    return ret;
  else
    return NULL;
}


struct exporter {
  assuan_context_t ctx;
  gcry_cipher_hd_t wrap_cipher;
  unsigned char *wrapped_key;
  size_t wrapped_len;
  unsigned char *unwrapped_key;
  size_t unwrapped_len;
  gcry_sexp_t sexp;
  gcry_mpi_t n;
  gcry_mpi_t e;
  gcry_mpi_t d;
  gcry_mpi_t p;
  gcry_mpi_t q;
};

gpg_error_t extend_wrapped_key (struct exporter *e, const void *data, size_t data_sz) {
  size_t newsz = e->wrapped_len + data_sz;
  unsigned char *wknew = realloc (e->wrapped_key, newsz);
  if (!wknew)
    return GPG_ERR_ENOMEM;
  memcpy (wknew + e->wrapped_len, data, data_sz);
  e->wrapped_key = wknew;
  e->wrapped_len = newsz;
  return GPG_ERR_NO_ERROR;
}

gpg_error_t unwrap_key (struct exporter *e) {
  unsigned char *out = NULL;
  gpg_error_t ret;
  const size_t sz_diff = 8;
  /* need 8 octets less:

     'GCRY_CIPHER_MODE_AESWRAP'
     This mode is used to implement the AES-Wrap algorithm according to
     RFC-3394.  It may be used with any 128 bit block length algorithm,
     however the specs require one of the 3 AES algorithms.  These
     special conditions apply: If 'gcry_cipher_setiv' has not been used
     the standard IV is used; if it has been used the lower 64 bit of
     the IV are used as the Alternative Initial Value.  On encryption
     the provided output buffer must be 64 bit (8 byte) larger than the
     input buffer; in-place encryption is still allowed.  On decryption
     the output buffer may be specified 64 bit (8 byte) shorter than
     then input buffer.  As per specs the input length must be at least
     128 bits and the length must be a multiple of 64 bits. */

  if ((e->ctx == NULL) ||
      (e->wrap_cipher == NULL) ||
      (e->wrapped_key == NULL) ||
      (e->wrapped_len < 1))
    return GPG_ERR_GENERAL; /* this exporter is not in the right state */


  out = realloc (e->unwrapped_key, e->wrapped_len - sz_diff);
  if (!out)
    return GPG_ERR_ENOMEM;
  e->unwrapped_key = out;
  e->unwrapped_len = e->wrapped_len - sz_diff;

  ret = gcry_cipher_decrypt (e->wrap_cipher,
                             e->unwrapped_key, e->unwrapped_len,
                             e->wrapped_key, e->wrapped_len);

  if (ret)
    return ret;
  ret = gcry_sexp_new(&e->sexp, e->unwrapped_key, e->unwrapped_len, 0);
  if (ret)
    return ret;
  
  /* RSA has: n, e, d, p, q */
  ret = gcry_sexp_extract_param (e->sexp, "private-key!rsa", "nedpq",
                                 &e->n, &e->e, &e->d, &e->p, &e->q, NULL);
  return ret;
}

gpg_error_t data_cb (void *arg, const void *data, size_t data_sz) {
  struct exporter *e = (struct exporter*)arg;
  gpg_error_t ret;

  if (e->wrap_cipher == NULL) {
    size_t cipher_keylen = gcry_cipher_get_algo_keylen(KEYWRAP_ALGO);
    if (data_sz != cipher_keylen) {
      fprintf (stderr, "wrong number of bytes in keywrap key (expected %zu, got %zu)\n",
               cipher_keylen, data_sz);
      return GPG_ERR_INV_KEYLEN;
    }
    ret = gcry_cipher_open (&(e->wrap_cipher), KEYWRAP_ALGO, KEYWRAP_ALGO_MODE, 0);
    if (ret)
      return ret;
    ret = gcry_cipher_setkey (e->wrap_cipher, data, data_sz);
    if (ret)
      return ret;
  } else {
    return extend_wrapped_key (e, data, data_sz);
  }
  return 0;
}
gpg_error_t inquire_cb (void *arg, const char *prompt) {
  fprintf (stderr, "inquire: %s\n", prompt);
  return 0;
}
gpg_error_t status_cb (void *arg, const char *status) {
  fprintf (stderr, "status: %s\n", status);
  return 0;
}

gpg_error_t transact (struct exporter *e, const char *command) {
  fprintf (stderr, "transaction: %s\n", command);
  return assuan_transact (e->ctx, command, data_cb, e, inquire_cb, e, status_cb, e);
}


gpg_error_t sendenv (struct exporter *e, const char *env, const char *val, const char *option_name) {
  char *str = NULL;
  gpg_error_t ret;
  int r;
  if (!val)
    val = getenv(env);

  /* skip env vars that are unset */
  if (!val)
    return GPG_ERR_NO_ERROR;
  if (option_name)
    r = asprintf (&str, "OPTION %s=%s", option_name, val);
  else
    r = asprintf (&str, "OPTION putenv=%s=%s", env, val);

  if (r <= 0)
    return GPG_ERR_ENOMEM;
  ret = transact (e, str);
  free (str);
  return ret;
}

void free_exporter (struct exporter *e) {
  assuan_release (e->ctx);
  if (e->wrap_cipher)
    gcry_cipher_close (e->wrap_cipher);
  free (e->wrapped_key);
  free (e->unwrapped_key);
  gcry_mpi_release(e->n);
  gcry_mpi_release(e->d);
  gcry_mpi_release(e->e);
  gcry_mpi_release(e->p);
  gcry_mpi_release(e->q);
  gcry_sexp_release (e->sexp);
}

void usage (FILE *f) {
  fprintf (f, "Usage: agent-extraction KEYGRIP\n"
           "  KEYGRIP should be a GnuPG keygrip (try gpg --with-keygrip --list-keys)\n"
           "\n"
           "Produces openssh-formatted secret key on stdout\n");
}

int main (int argc, const char* argv[]) {
  gpg_error_t err;
  char *agent_socket = NULL;
  char *get_key = NULL;
  int idx = 0;
  struct exporter e = { .wrapped_key = NULL };

  if (!gcry_check_version (GCRYPT_VERSION)) {
    fprintf (stderr, "libgcrypt version mismatch\n");
    return 1;
  }
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  
  if ((argc != 2) || (strlen(argv[1]) != KEYGRIP_LENGTH)) {
    usage (stderr);
    return 1;
  }
  for (idx = 0; idx < KEYGRIP_LENGTH; idx++) {
    if (!isxdigit(argv[1][idx])) {
      fprintf (stderr, "keygrips must be 40 hex digits\n");
      return 1;
    }
  }

  if (asprintf (&get_key, "export_key %s", argv[1]) < 0) {
    fprintf (stderr, "failed to generate key export string\n");
    return 1;
  }
    
  
  /* assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT); */
  /*  assuan_set_log_cb (log, NULL); */
  err = assuan_new (&(e.ctx));
  if (err) {
    fprintf (stderr, "failed to create assuan context (%d) (%s)\n", err, gpg_strerror(err));
    return 1;
  }
  agent_socket = agent_sockname();
  
  /* FIXME: launch gpg-agent if it is not already connected */
  assuan_socket_connect (e.ctx, agent_socket, ASSUAN_INVALID_PID, ASSUAN_SOCKET_CONNECT_FDPASSING);

  /* FIXME: what do we do if "getinfo std_env_names includes something new? */
  struct { const char *env; const char *val; const char *opt; } vars[] = {
    { .env = "GPG_TTY", .val = ttyname(0), .opt = "ttyname" },
    { .env = "TERM", .opt = "ttytype" },
    { .env = "DISPLAY", .opt = "display" },
    { .env = "XAUTHORITY", .opt = "xauthority" },
    { .env = "GTK_IM_MODULE" },
    { .env = "DBUS_SESSION_BUS_ADDRESS" },
    { .env = "LANG", .opt = "lc-ctype" },
    { .env = "LANG", .opt = "lc-messages" } };
  for (idx = 0; idx < sizeof(vars)/sizeof(vars[0]); idx++) {
    if (err = sendenv (&e, vars[idx].env, vars[idx].val, vars[idx].opt), err) {
      fprintf (stderr, "failed to set %s (%s)\n", vars[idx].opt ? vars[idx].opt : vars[idx].env,
               gpg_strerror(err));
    }
  }
  /* FIXME: set up the agent prompt */
  err = transact (&e, "keywrap_key --export");
  if (err) {
    fprintf (stderr, "failed to export keywrap key (%d), %s\n", err, gpg_strerror(err));
    return 1;
  }
  err = transact (&e, get_key);
  if (err) {
    fprintf (stderr, "failed to export secret key %s (%d), %s\n", argv[1], err, gpg_strerror(err));
    return 1;
  }
  err = unwrap_key (&e);
  if (err) {
    fprintf (stderr, "failed to unwrap secret key (%d), %s\n", err, gpg_strerror(err));
    return 1;
  }

  fprintf (stderr, "n: %d\n", gcry_mpi_get_nbits(e.n));
  fprintf (stderr, "e: %d\n", gcry_mpi_get_nbits(e.e));
  fprintf (stderr, "d: %d\n", gcry_mpi_get_nbits(e.d));
  fprintf (stderr, "p: %d\n", gcry_mpi_get_nbits(e.p));
  fprintf (stderr, "q: %d\n", gcry_mpi_get_nbits(e.q));

  /*  fwrite (e.unwrapped_key, e.unwrapped_len, 1, stdout); */
  
  free (agent_socket);
  free (get_key);
  free_exporter (&e);
  return 0;
}
