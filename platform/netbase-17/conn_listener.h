#pragma once

#include "netb.h"



class conn_listener {
public:

	int init();

  void loop();

protected:
  conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
    enum network_transport transport, struct event_base *base, void *ssl);

  void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size,
    enum network_transport transport, void *ssl);

	void maximize_sndbuf(const int sfd);

	int new_socket(struct addrinfo *ai);

	int server_socket(const char *interfaces,
		int port,
		enum network_transport transport,
		FILE *portnumber_file, bool ssl_enabled);

	int server_sockets(int port, enum network_transport transport,
		FILE *portnumber_file);


protected:
	struct settings settings;

  static bool stop_main_loop;
  static conn *listen_conn;
  static struct event_base *main_base;

};

