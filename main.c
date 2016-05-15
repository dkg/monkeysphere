#define _GNU_SOURCE
#include <stdio.h>
#include <assuan.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>


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


gpg_error_t data_cb (void *arg, const void *data, size_t data_sz) {
  fprintf (stderr, "data: %zu octets\n", data_sz);
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


int main (int argc, const char* argv[]) {
  assuan_context_t ctx;
  gpg_error_t err;
  char *agent_socket = NULL;
  
  /* assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT); */
  /*  assuan_set_log_cb (log, NULL); */
  err = assuan_new (&ctx);
  if (err) {
    fprintf (stderr, "failed to create assuan context (%d) (%s)\n", err, gpg_strerror(err));
    return 1;
  }
  agent_socket = agent_sockname();
  
  /* FIXME: launch gpg-agent if it is not already connected */
  assuan_socket_connect (ctx, agent_socket, ASSUAN_INVALID_PID, ASSUAN_SOCKET_CONNECT_FDPASSING);

  assuan_transact (ctx, "getinfo version",
                   data_cb, NULL,
                   inquire_cb, NULL,
                   status_cb, NULL);

  free(agent_socket);
  assuan_release(ctx);
}
