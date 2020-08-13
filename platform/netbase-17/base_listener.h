#pragma once

#include "netb.h"
#include "thread.h"

class base_listener : public netb::thread {
public:

  //需要conn的factory，conn的派生类对应具体处理的业务
  base_listener();


  bool init();


protected:
  void maximize_sndbuf(const int sfd);

  int new_socket(struct addrinfo *ai);

  int server_socket(const char *interfaces,
    int port,
    enum network_transport transport,
    FILE *portnumber_file, bool ssl_enabled);

  int server_sockets(int port, enum network_transport transport,
    FILE *portnumber_file);


protected:
  static void event_handler(const int fd, const short which, void *arg);


protected:
  void conn_init(void);
  void conn_free(conn *c);

  virtual conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
    enum network_transport transport, struct event_base *base, void *ssl) override;

protected:


  static struct settings settings;

  static conn **conns;
  static int max_fds;

  static bool stop_main_loop;
  static conn *listen_conn;
  static struct event_base *main_base;
};

