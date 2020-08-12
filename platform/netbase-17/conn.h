#pragma once


#include "netb.h"

void conn_init(int max_fds);

conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
	enum network_transport transport, struct event_base *base, void *ssl);
void conn_free(conn *c);

void conn_close(conn *c);

