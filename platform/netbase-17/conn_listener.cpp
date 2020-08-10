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
	struct addrinfo hints;
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
	error = getaddrinfo(interfaces, port_buf, &hints, &ai);
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
				exit(-1/*EX_OSERR*/);
			}
			continue;
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