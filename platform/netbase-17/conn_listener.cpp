#include "conn_listener.h"

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
/* Avoid warnings on solaris, where isspace() is an index into an array, and gcc uses signed chars */
#define xisspace(c) isspace((unsigned char)c)
bool safe_strtol(const char *str, int32_t *out) {
	assert(out != NULL);
	errno = 0;
	*out = 0;
	char *endptr;
	long l = strtol(str, &endptr, 10);
	if ((errno == ERANGE) || (str == endptr)) {
		return false;
	}

	if (xisspace(*endptr) || (*endptr == '\0' && endptr != str)) {
		*out = l;
		return true;
	}
	return false;
}



int conn_listener::init()
{
	memset(&settings, 0, sizeof settings);
	settings.port = 11211;

	/* create the listening socket, bind it, and init */
	if (settings.socketpath == NULL) {
		const char *portnumber_filename = getenv("MEMCACHED_PORT_FILENAME");
		char *temp_portnumber_filename = NULL;
		size_t len;
		FILE *portnumber_file = NULL;

		if (portnumber_filename != NULL) {
			len = strlen(portnumber_filename) + 4 + 1;
			temp_portnumber_filename = (char*)malloc(len);
			snprintf(temp_portnumber_filename,
				len,
				"%s.lck", portnumber_filename);

			portnumber_file = fopen(temp_portnumber_filename, "a");
			if (portnumber_file == NULL) {
				fprintf(stderr, "Failed to open \"%s\": %s\n",
					temp_portnumber_filename, strerror(errno));
			}
		}

		errno = 0;
		if (settings.port && server_sockets(settings.port, tcp_transport,
			portnumber_file)) {
			printf("failed to listen on TCP port %d", settings.port);
			exit(EX_OSERR);
		}

		/*
		 * initialization order: first create the listening sockets
		 * (may need root on low ports), then drop root if needed,
		 * then daemonize if needed, then init libevent (in some cases
		 * descriptors created by libevent wouldn't survive forking).
		 */

		 /* create the UDP listening socket and bind it */
		errno = 0;
		if (settings.udpport && server_sockets(settings.udpport, udp_transport,
			portnumber_file)) {
			printf("failed to listen on UDP port %d", settings.udpport);
			exit(EX_OSERR);
		}

		if (portnumber_file) {
			fclose(portnumber_file);
			rename(temp_portnumber_filename, portnumber_filename);
		}
		if (temp_portnumber_filename)
			free(temp_portnumber_filename);
	}

}

void conn_listener::maximize_sndbuf(const int sfd)
{
	socklen_t intsize = sizeof(int);
	int last_good = 0;
	int min, max, avg;
	int old_size;

	/* Start with the default size. */
	if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (char*)&old_size, &intsize) != 0) {
		if (settings.verbose > 0)
			perror("getsockopt(SO_SNDBUF)");
		return;
	}

	/* Binary-search for the real maximum. */
	min = old_size;
	max = MAX_SENDBUF_SIZE;

	while (min <= max) {
		avg = ((unsigned int)(min + max)) / 2;
		if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (const char *)&avg, intsize) == 0) {
			last_good = avg;
			min = avg + 1;
		}
		else {
			max = avg - 1;
		}
	}

	if (settings.verbose > 1)
		fprintf(stderr, "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
}

int conn_listener::new_socket(struct addrinfo *ai)
{
	int sfd;
	int flags;

	if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
		return -1;
	}
}

int conn_listener::server_socket(const char *interfaces,
	int port,
	enum network_transport transport,
	FILE *portnumber_file, bool ssl_enabled) {
	int sfd;
	struct linger ling = { 0, 0 };
	struct addrinfo *ai;
	struct addrinfo *next;

	/*NOT support in windows*/
// 	struct addrinfo hints = { 
// 		.ai_flags = AI_PASSIVE,
// 		.ai_family = AF_UNSPEC
// 	};
	struct addrinfo hints = {0};
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;

	char port_buf[NI_MAXSERV];
	int error;
	int success = 0;
	int flags = 1;

	hints.ai_socktype = IS_UDP(transport) ? SOCK_DGRAM : SOCK_STREAM;

	if (port == -1) {
		port = 0;
	}
	snprintf(port_buf, sizeof(port_buf), "%d", port);
	//error = getaddrinfo(interfaces, port_buf, &hints, &ai);
	error = getaddrinfo("192.168.101.9", port_buf, &hints, &ai);
	if (error != 0) {
#ifndef _WIN32
		if (error != EAI_SYSTEM)
#else
		if (error != EAI_FAIL)
#endif
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
		else
			perror("getaddrinfo()");
		return 1;
	}

	for (next = ai; next; next = next->ai_next) {
		conn *listen_conn_add;
		if ((sfd = new_socket(next)) == -1) {
			/* getaddrinfo can return "junk" addresses,
			 * we make sure at least one works before erroring.
			 */
			if (errno == EMFILE) {
				/* ...unless we're out of fds */
				perror("server_socket");
				exit(EX_OSERR);
			}
			continue;
		}

#ifdef IPV6_V6ONLY
		if (next->ai_family == AF_INET6) {
			error = setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flags, sizeof(flags));
			if (error != 0) {
				perror("setsockopt");
				//close(sfd);
				closesocket(sfd);
				continue;
			}
		}
#endif


		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&flags, sizeof(flags));
		if (IS_UDP(transport)) {
			maximize_sndbuf(sfd);
		}
		else {
			error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&flags, sizeof(flags));
			if (error != 0)
				perror("setsockopt");

			error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (const char *)&ling, sizeof(ling));
			if (error != 0)
				perror("setsockopt");

			error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&flags, sizeof(flags));
			if (error != 0)
				perror("setsockopt");
		}

		if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
			if (errno != EADDRINUSE) {
				perror("bind()");
				closesocket(sfd);
				freeaddrinfo(ai);
				return 1;
			}
			closesocket(sfd);
			continue;
		}
		else {
			success++;
			if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1) {
				perror("listen()");
				closesocket(sfd);
				freeaddrinfo(ai);
				return 1;
			}
			if (portnumber_file != NULL &&
				(next->ai_addr->sa_family == AF_INET ||
					next->ai_addr->sa_family == AF_INET6)) {
				union {
					struct sockaddr_in in;
					struct sockaddr_in6 in6;
				} my_sockaddr;
				socklen_t len = sizeof(my_sockaddr);
				if (getsockname(sfd, (struct sockaddr*)&my_sockaddr, &len) == 0) {
					if (next->ai_addr->sa_family == AF_INET) {
						fprintf(portnumber_file, "%s INET: %u\n",
							IS_UDP(transport) ? "UDP" : "TCP",
							ntohs(my_sockaddr.in.sin_port));
					}
					else {
						fprintf(portnumber_file, "%s INET6: %u\n",
							IS_UDP(transport) ? "UDP" : "TCP",
							ntohs(my_sockaddr.in6.sin6_port));
					}
				}
			}
		}
	}


	return 0;
}

int conn_listener::server_sockets(int port, enum network_transport transport, FILE *portnumber_file)
{
	bool ssl_enabled = false;

#ifdef TLS
	const char *notls = "notls";
	ssl_enabled = settings.ssl_enabled;
#endif

	if (settings.inter == NULL) {
		return server_socket(settings.inter, port, transport, portnumber_file, ssl_enabled);
	}
	else {
		// tokenize them and bind to each one of them..
		char *b;
		int ret = 0;
		char *list = _strdup(settings.inter);

		if (list == NULL) {
			fprintf(stderr, "Failed to allocate memory for parsing server interface string\n");
			return 1;
		}
#ifndef _WIN32 
		for (char *p = strtok_r(list, ";,", &b);
			p != NULL;
			p = strtok_r(NULL, ";,", &b)) {
#else
		for (char *p = strtok_s(list, ";,", &b);
			p != NULL;
			p = strtok_s(NULL, ";,", &b)) {
#endif
			int the_port = port;
#ifdef TLS
			ssl_enabled = settings.ssl_enabled;
			// "notls" option is valid only when memcached is run with SSL enabled.
			if (strncmp(p, notls, strlen(notls)) == 0) {
				if (!settings.ssl_enabled) {
					fprintf(stderr, "'notls' option is valid only when SSL is enabled\n");
					free(list);
					return 1;
				}
				ssl_enabled = false;
				p += strlen(notls) + 1;
			}
#endif

			char *h = NULL;
			if (*p == '[') {
				// expecting it to be an IPv6 address enclosed in []
				// i.e. RFC3986 style recommended by RFC5952
				char *e = strchr(p, ']');
				if (e == NULL) {
					fprintf(stderr, "Invalid IPV6 address: \"%s\"", p);
					free(list);
					return 1;
				}
				h = ++p; // skip the opening '['
				*e = '\0';
				p = ++e; // skip the closing ']'
			}

			char *s = strchr(p, ':');
			if (s != NULL) {
				// If no more semicolons - attempt to treat as port number.
				// Otherwise the only valid option is an unenclosed IPv6 without port, until
				// of course there was an RFC3986 IPv6 address previously specified -
				// in such a case there is no good option, will just send it to fail as port number.
				if (strchr(s + 1, ':') == NULL || h != NULL) {
					*s = '\0';
					++s;
					if (!safe_strtol(s, &the_port)) {
						fprintf(stderr, "Invalid port number: \"%s\"", s);
						free(list);
						return 1;
					}
				}
			}

			if (h != NULL)
				p = h;

			if (strcmp(p, "*") == 0) {
				p = NULL;
			}
			ret |= server_socket(p, the_port, transport, portnumber_file, ssl_enabled);
		}
		free(list);
		return ret;
	}
}