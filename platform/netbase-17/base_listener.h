#pragma once

#include "netb.h"
#include "thread.h"
#include "conn_factory.h"

class base_listener : public netb::thread {
public:

  //需要conn的factory，conn的派生类对应具体处理的业务
  base_listener();
  base_listener(struct settings& settings, conn_factory* factory);


  bool init();

  void loop();


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
  static bool rbuf_alloc(conn *c);

  static void rbuf_release(conn *c);

  static bool update_event(conn *c, const int new_flags);

  static void reset_cmd_handler(conn *c);

  static void drive_machine(conn *c);

  static void event_handler(const int fd, const short which, void *arg);

  static void conn_close(conn *c);

  static void conn_cleanup(conn *c);

  static void conn_set_state(conn *c, enum conn_states state);
protected:

  virtual conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
    enum network_transport transport, struct event_base *base, void *ssl) override;

protected:

  conn_factory* factory;
  struct settings settings;

  static int max_fds;

  static bool stop_main_loop;
  static conn *listen_conn;
  static struct event_base *main_base;
};

