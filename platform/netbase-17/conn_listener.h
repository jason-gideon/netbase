#pragma once

#include "netb.h"



class conn_listener {
public:

	int init();

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
	struct settings settings;

};

