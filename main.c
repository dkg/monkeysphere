#define _GNU_SOURCE
#include <stdio.h>
#include <assuan.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <gcrypt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

#include "ssh-agent-proto.h"

#define KEYGRIP_LENGTH 40
#define KEYWRAP_ALGO GCRY_CIPHER_AES128
#define KEYWRAP_ALGO_MODE GCRY_CIPHER_MODE_AESWRAP


int custom_log (assuan_context_t ctx, void *hook, unsigned int cat, const char *msg) {
  fprintf (stderr, "assuan (cat %d), %s\n", cat, msg);
  return 1;
}

char* gpg_agent_sockname () {
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
  gcry_mpi_t iqmp;
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
  if (ret)
    return ret;

  e->iqmp = gcry_mpi_new(0);
  ret = gcry_mpi_invm (e->iqmp, e->q, e->p);

  if (!ret) {
    fprintf (stderr, "Could not calculate the (inverse of q) mod p\n");
    return GPG_ERR_GENERAL;
  } else {
    return GPG_ERR_NO_ERROR;
  }
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

size_t get_ssh_sz (gcry_mpi_t mpi) {
  size_t wid;
  gcry_mpi_print (GCRYMPI_FMT_SSH, NULL, 0, &wid, mpi);
  return wid;
}

int send_to_ssh_agent(struct exporter *e, int fd, unsigned int seconds, int confirm, const char *comment) {
  const char *key_type = "ssh-rsa";
  int ret;
  size_t len;
  off_t offset;
  unsigned char *msgbuf = NULL;
  uint32_t tmp;
  size_t slen;
  ssize_t written, bytesread;
  unsigned char resp;
  
  len = 1 + /* request byte */
    4 + strlen(key_type) + /* type of key */
    get_ssh_sz (e->n) +
    get_ssh_sz (e->e) +
    get_ssh_sz (e->d) +
    get_ssh_sz (e->iqmp) +
    get_ssh_sz (e->p) +
    get_ssh_sz (e->q) +
    4 + (comment ? strlen (comment) : 0) +
    (confirm ? 1 : 0) +
    (seconds ? 5 : 0);

  msgbuf = malloc (4 + len);
  if (msgbuf == NULL) {
    fprintf (stderr, "could not allocate %zu bytes for the message to ssh-agent\n", 4 + len);
    return -1;
  }

#define w32(a) { tmp = htonl(a); memcpy(msgbuf + offset, &tmp, sizeof(tmp)); offset += sizeof(tmp); }
#define wstr(a) { slen = (a ? strlen (a) : 0); w32 (slen); if (a) memcpy (msgbuf + offset, a, slen); offset += slen; }
#define wbyte(x) { msgbuf[offset] = (x); offset += 1; }
#define wmpi(n) { ret = gcry_mpi_print (GCRYMPI_FMT_SSH, msgbuf + offset, get_ssh_sz (n), &slen, n); \
    if (ret) { fprintf (stderr, "failed writing ssh mpi " #n "\n"); free (msgbuf); return -1; }; offset += slen; }

  offset = 0;
  
  w32 (len);
  wbyte (seconds || confirm ? SSH2_AGENTC_ADD_ID_CONSTRAINED : SSH2_AGENTC_ADD_IDENTITY);
  wstr (key_type);
  wmpi (e->n);
  wmpi (e->e);
  wmpi (e->d);
  wmpi (e->iqmp);
  wmpi (e->p);
  wmpi (e->q);
  wstr (comment);
  if (confirm)
    wbyte (SSH_AGENT_CONSTRAIN_CONFIRM);
  if (seconds) {
    wbyte (SSH_AGENT_CONSTRAIN_LIFETIME);
    w32 (seconds);
  }
  written = write (fd, msgbuf, 4+len);
  if (written != 4 + len) {
    fprintf (stderr, "failed writing message to ssh agent socket (%zd) (errno: %d)\n", written, errno);
    free (msgbuf);
    return -1;
  }
  free (msgbuf);

  /* FIXME: this could actually be done in a select loop if we think the
     ssh-agent will dribble out its response or not respond immediately.*/
  bytesread = read (fd, &tmp, sizeof (tmp));
  if (bytesread != sizeof (tmp)) {
    fprintf (stderr, "failed to get %zu bytes from ssh-agent (got %zd)\n", sizeof (tmp), bytesread);
    return -1;
  }
  slen = ntohl (tmp);
  if (slen != sizeof(resp)) {
    fprintf (stderr, "ssh-agent response was wrong size (expected: %zu; got %zu)\n", sizeof(resp), slen);
    return -1;
  }
  bytesread = read (fd, &resp, sizeof (resp));
  if (bytesread != sizeof (resp)) {
    fprintf (stderr, "failed to get %zu bytes from ssh-agent (got %zd)\n", sizeof (resp), bytesread);
    return -1;
  }
  if (resp != SSH_AGENT_SUCCESS) {
    fprintf (stderr, "ssh-agent did not claim success (expected: %d; got %d)\n",
             SSH_AGENT_SUCCESS, resp);
    return -1;
  }    
    
  return 0;
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
  gcry_mpi_release(e->iqmp);
  gcry_sexp_release (e->sexp);
}

void usage (FILE *f) {
  fprintf (f, "Usage: agent-extraction [options] KEYGRIP [COMMENT]\n"
           "\n"
           "Extracts a secret key from the GnuPG agent (by keygrip),\n"
           "and sends it to the running SSH agent.\n"
           "\n"
           "  KEYGRIP should be a GnuPG keygrip\n"
           "    (e.g. try \"gpg --with-keygrip --list-keys\")\n"
           "  COMMENT (optional) can be any string\n"
           "    (must not start with a \"-\")\n"
           "\n"
           "Options:\n"
           " -t SECONDS  lifetime (in seconds) for the key to live in the ssh-agent\n"
           " -c          require confirmation when using the key\n"
           " -h          print this help\n"
           );
}

int get_ssh_auth_sock_fd() {
  char *sock_name = getenv("SSH_AUTH_SOCK");
  struct sockaddr_un sockaddr;
  int ret = -1;
  if (sock_name == NULL) {
    fprintf (stderr, "SSH_AUTH_SOCK is not set, cannot talk to agent.\n");
    return -1;
  }
  if (strlen(sock_name) + 1 > sizeof(sockaddr.sun_path)) {
    fprintf (stderr, "SSH_AUTH_SOCK (%s) is larger than the maximum allowed socket path (%zu)\n",
             sock_name, sizeof(sockaddr.sun_path));
    return -1;
  }
  sockaddr.sun_family = AF_UNIX;
  strncpy(sockaddr.sun_path, sock_name, sizeof(sockaddr.sun_path) - 1);
  sockaddr.sun_path[sizeof(sockaddr.sun_path) - 1] = '\0';
  ret = socket (AF_UNIX, SOCK_STREAM, 0);
  if (ret == -1) {
    fprintf (stderr, "Could not open a socket file descriptor\n");
    return ret;
  }
  if (-1 == connect (ret, &sockaddr, sizeof(sockaddr))) {
    fprintf (stderr, "Failed to connect to ssh agent socket %s\n", sock_name);
    close (ret);
    return -1;
  }

  return ret;
}

struct args {
  int seconds;
  int confirm;
  const char *comment;
  const char *keygrip;
  int help;
};

int parse_args (int argc, const char **argv, struct args *args) {
  int ptr = 1;
  int idx = 0;

  while (ptr < argc) {
    if (argv[ptr][0] == '-') {
      int looking_for_seconds = 0;
      const char *x = argv[ptr] + 1;
      while (*x != '\0') {
        switch (*x) {
        case 'c':
          args->confirm = 1;
          break;
        case 't':
          looking_for_seconds = 1;
          break;
        case 'h':
          args->help = 1;
          break;
        default:
          fprintf (stderr, "flag not recognized: %c\n", *x);
          return 1;
        }
        x++;
      }
      if (looking_for_seconds) {
        if (argc <= ptr + 1) {
          fprintf (stderr, "lifetime (-t) needs an argument (number of seconds)\n");
          return 1;
        }
        args->seconds = atoi (argv[ptr + 1]);
        if (args->seconds <= 0) {
          fprintf (stderr, "lifetime (seconds) must be > 0\n");
          return 1;
        }
        ptr += 1;
      }
    } else {
      if (args->keygrip == NULL) {
        if (strlen (argv[ptr]) != KEYGRIP_LENGTH) {
          fprintf (stderr, "keygrip must be 40 hexadecimal digits\n");
          return 1;
        }
        
        for (idx = 0; idx < KEYGRIP_LENGTH; idx++) {
          if (!isxdigit(argv[ptr][idx])) {
            fprintf (stderr, "keygrip must be 40 hexadecimal digits\n");
            return 1;
          }
        }
        args->keygrip = argv[ptr];
      } else {
        if (args->comment == NULL) {
          args->comment = argv[ptr];
        } else {
          fprintf (stderr, "unrecognized argument %s\n", argv[ptr]);
          return 1;
        }
      }
    }
    ptr += 1;
  };
  
  return 0;
}

int main (int argc, const char* argv[]) {
  gpg_error_t err;
  char *gpg_agent_socket = NULL;
  int ssh_sock_fd = 0;
  char *get_key = NULL, *desc_prompt = NULL;
  int idx = 0, ret = 0;
  struct exporter e = { .wrapped_key = NULL };
  /* ssh agent constraints: */
  struct args args = { .keygrip = NULL };
  
  if (!gcry_check_version (GCRYPT_VERSION)) {
    fprintf (stderr, "libgcrypt version mismatch\n");
    return 1;
  }
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  
  if (parse_args(argc, argv, &args)) {
    usage (stderr);
    return -1;
  }

  if (args.help) {
    usage (stdout);
    return 0;
  }

  if (asprintf (&get_key, "EXPORT_KEY %s", args.keygrip) < 0) {
    fprintf (stderr, "failed to generate key export string\n");
    return 1;
  }

  /* FIXME: include "plus-percent-escaped" comment in this string, if comment exists */
  ret = asprintf (&desc_prompt, "SETKEYDESC Sending+key+from+gpg-agent+to+ssh-agent...%%0a"
                  "(keygrip:+%s)",
                  args.keygrip);
  
  if (ret < 0) {
    fprintf (stderr, "failed to generate prompt description\n");
    return 1;
  }

  ssh_sock_fd = get_ssh_auth_sock_fd();
  if (ssh_sock_fd == -1)
    return 1;
  
  err = assuan_new (&(e.ctx));
  if (err) {
    fprintf (stderr, "failed to create assuan context (%d) (%s)\n", err, gpg_strerror (err));
    return 1;
  }
  gpg_agent_socket = gpg_agent_sockname();
  
  /* launch gpg-agent if it is not already connected */
  err = assuan_socket_connect (e.ctx, gpg_agent_socket,
                               ASSUAN_INVALID_PID, ASSUAN_SOCKET_CONNECT_FDPASSING);
  if (err) {
    if (gpg_err_code (err) != GPG_ERR_ASS_CONNECT_FAILED) {
      fprintf (stderr, "failed to connect to gpg-agent socket (%d) (%s)\n",
               err, gpg_strerror (err));
    } else {
      fprintf (stderr, "could not find gpg-agent, trying to launch it...\n");
      int r = system ("gpgconf --launch gpg-agent");
      if (r) {
        fprintf (stderr, "failed to launch gpg-agent\n");
        return 1;
      }
      /* try to connect again: */
      err = assuan_socket_connect (e.ctx, gpg_agent_socket,
                               ASSUAN_INVALID_PID, ASSUAN_SOCKET_CONNECT_FDPASSING);
      if (err) {
        fprintf (stderr, "failed to connect to gpg-agent after launching (%d) (%s)\n",
                 err, gpg_strerror (err));
        return 1;
      }
    }
  }

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
  err = transact (&e, "keywrap_key --export");
  if (err) {
    fprintf (stderr, "failed to export keywrap key (%d), %s\n", err, gpg_strerror(err));
    return 1;
  }
  err = transact (&e, desc_prompt);
  if (err) {
    fprintf (stderr, "failed to set the description prompt (%d), %s\n", err, gpg_strerror(err));
    return 1;
  }
  err = transact (&e, get_key);
  if (err) {
    fprintf (stderr, "failed to export secret key %s (%d), %s\n", args.keygrip, err, gpg_strerror(err));
    return 1;
  }
  err = unwrap_key (&e);
  if (err) {
    fprintf (stderr, "failed to unwrap secret key (%d), %s\n", err, gpg_strerror(err));
    return 1;
  }

  err = send_to_ssh_agent (&e, ssh_sock_fd, args.seconds, args.confirm, args.comment);
  if (err)
    return 1;
  
  /*  fwrite (e.unwrapped_key, e.unwrapped_len, 1, stdout); */

  close (ssh_sock_fd);
  free (gpg_agent_socket);
  free (get_key);
  free (desc_prompt);
  free_exporter (&e);
  return 0;
}
