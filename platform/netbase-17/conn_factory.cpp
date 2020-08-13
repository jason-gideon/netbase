#include "conn_factory.h"

#include <assert.h>

conn_factory::conn_factory(int maxconns)
  : max_fds(maxconns) {
  conn_init();
}

void conn_factory::conn_init(void) {
#ifndef _WIN32
  /* We're unlikely to see an FD much higher than maxconns. */
  int next_fd = dup(1);
  if (next_fd < 0) {
    perror("Failed to duplicate file descriptor\n");
    exit(1);
  }
  int headroom = 10;      /* account for extra unexpected open FDs */
  struct rlimit rl;

  max_fds = max_fds /*settings.maxconns*/ + headroom + next_fd;

  /* But if possible, get the actual highest FD we can possibly ever see. */
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
    max_fds = rl.rlim_max;
  }
  else {
    fprintf(stderr, "Failed to query maximum file descriptor; "
      "falling back to maxconns\n");
  }

  close(next_fd);

  conns.resize(max_fds);
#else
  conns.resize(max_fds);
#endif	
}

conn * conn_factory::conn_new(int sfd) {
  conn* c;

  std::lock_guard<std::mutex> lck(mtx);

  assert(sfd >= 0 && sfd < max_fds);
  c = conns[sfd];

  if (NULL == c) {
    if (!(c = create_task_node())) {
      return NULL;
    }
    
    conns[sfd] = c;
  }

  return c;
}

void conn_factory::conn_free(conn *c)
{
  if (c) {
    assert(c != NULL);
    assert(c->sfd >= 0 && c->sfd < max_fds);

    //MEMCACHED_CONN_DESTROY(c);
    conns[c->sfd] = NULL;
    if (c->rbuf)
      free(c->rbuf);
#ifdef TLS
    if (c->ssl_wbuf)
      c->ssl_wbuf = NULL;
#endif

    free(c);
  }
}
