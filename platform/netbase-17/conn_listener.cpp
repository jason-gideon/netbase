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




struct settings conn_listener::settings;

conn ** conn_listener::conns = nullptr;
int conn_listener::max_fds = 0;

bool conn_listener::stop_main_loop = false;

conn * conn_listener::listen_conn = nullptr;
struct event_base * conn_listener::main_base = nullptr;

int conn_listener::init()
{
	memset(&settings, 0, sizeof settings);
	settings.port = 11211;
	settings.udpport = 22422;
	settings.backlog = 1000;
	settings.maxconns = 10000;

	/* initialize main thread libevent instance */
#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000101
	/* If libevent version is larger/equal to 2.0.2-alpha, use newer version */
	struct event_config *ev_config;
	ev_config = event_config_new();
	event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
	main_base = event_base_new_with_config(ev_config);
	event_config_free(ev_config);
#else
	/* Otherwise, use older API */
	main_base = event_init();
#endif



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


void conn_listener::loop()
{
	/* enter the event loop */
	while (!stop_main_loop) {
		if (event_base_loop(main_base, EVLOOP_ONCE) != 0) {
			//retval = EXIT_FAILURE;
			break;
		}
	}
}


/*
 * Initializes the connections array. We don't actually allocate connection
 * structures until they're needed, so as to avoid wasting memory when the
 * maximum connection count is much higher than the actual number of
 * connections.
 *
 * This does end up wasting a few pointers' worth of memory for FDs that are
 * used for things other than connections, but that's worth it in exchange for
 * being able to directly index the conns array by FD.
 */
void conn_listener::conn_init(void)
{
#ifndef _WIN32
	/* We're unlikely to see an FD much higher than maxconns. */
	int next_fd = dup(1);
	if (next_fd < 0) {
		perror("Failed to duplicate file descriptor\n");
		exit(1);
	}
	int headroom = 10;      /* account for extra unexpected open FDs */
	struct rlimit rl;

	max_fds = settings.maxconns + headroom + next_fd;

	/* But if possible, get the actual highest FD we can possibly ever see. */
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		max_fds = rl.rlim_max;
	}
	else {
		fprintf(stderr, "Failed to query maximum file descriptor; "
			"falling back to maxconns\n");
	}

	close(next_fd);

	if ((conns = (conn**)calloc(max_fds, sizeof(conn *))) == NULL) {
		fprintf(stderr, "Failed to allocate connection structures\n");
		/* This is unrecoverable so bail out early. */
		exit(1);
}
#else
	max_fds = settings.maxconns;
	if ((conns = (conn**)calloc(max_fds, sizeof(conn *))) == NULL) {
		fprintf(stderr, "Failed to allocate connection structures\n");
		/* This is unrecoverable so bail out early. */
		exit(1);
	}
#endif	

}

conn * conn_listener::conn_new(const int sfd, enum conn_states init_state,
	const int event_flags,
	const int read_buffer_size, enum network_transport transport,
	struct event_base *base, void *ssl) {
	conn *c;

	assert(sfd >= 0 && sfd < max_fds);
	c = conns[sfd];

	if (NULL == c) {
		if (!(c = (conn *)calloc(1, sizeof(conn)))) {
			//STATS_LOCK();
// 			stats.malloc_fails++;
// 			STATS_UNLOCK();
			fprintf(stderr, "Failed to allocate connection object\n");
			return NULL;
		}
		//MEMCACHED_CONN_CREATE(c);
		c->read = NULL;
		c->sendmsg = NULL;
		c->write = NULL;
		c->rbuf = NULL;

		c->rsize = read_buffer_size;

		// UDP connections use a persistent static buffer.
		if (c->rsize) {
			c->rbuf = (char *)malloc((size_t)c->rsize);
		}

		if (c->rsize && c->rbuf == NULL) {
			conn_free(c);
// 			STATS_LOCK();
// 			stats.malloc_fails++;
// 			STATS_UNLOCK();
			fprintf(stderr, "Failed to allocate buffers for connection\n");
			return NULL;
		}

// 		STATS_LOCK();
// 		stats_state.conn_structs++;
// 		STATS_UNLOCK();

		c->sfd = sfd;
		conns[sfd] = c;
	}

	c->transport = transport;
	//c->protocol = settings.binding_protocol;

	/* unix socket mode doesn't need this, so zeroed out.  but why
	 * is this done for every command?  presumably for UDP
	 * mode.  */
	if (!settings.socketpath) {
		c->request_addr_size = sizeof(c->request_addr);
	}
	else {
		c->request_addr_size = 0;
	}

	if (transport == tcp_transport && init_state == conn_new_cmd) {
		if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
			&c->request_addr_size)) {
			perror("getpeername");
			memset(&c->request_addr, 0, sizeof(c->request_addr));
		}
	}

// 	if (settings.verbose > 1) {
// 		if (init_state == conn_listening) {
// 			fprintf(stderr, "<%d server listening (%s)\n", sfd,
// 				prot_text(c->protocol));
// 		}
// 		else if (IS_UDP(transport)) {
// 			fprintf(stderr, "<%d server listening (udp)\n", sfd);
// 		}
// 		else if (c->protocol == negotiating_prot) {
// 			fprintf(stderr, "<%d new auto-negotiating client connection\n",
// 				sfd);
// 		}
// 		else if (c->protocol == ascii_prot) {
// 			fprintf(stderr, "<%d new ascii client connection.\n", sfd);
// 		}
// 		else if (c->protocol == binary_prot) {
// 			fprintf(stderr, "<%d new binary client connection.\n", sfd);
// 		}
// 		else {
// 			fprintf(stderr, "<%d new unknown (%d) client connection\n",
// 				sfd, c->protocol);
// 			assert(false);
// 		}
// 	}

#ifdef TLS
	c->ssl = NULL;
	c->ssl_wbuf = NULL;
	c->ssl_enabled = false;
#endif
	c->state = init_state;
	c->rlbytes = 0;
	c->cmd = -1;
	c->rbytes = 0;
	c->rcurr = c->rbuf;
	c->ritem = 0;
	c->rbuf_malloced = false;
	c->sasl_started = false;
	c->set_stale = false;
	c->mset_res = false;
	c->close_after_write = false;
	//c->last_cmd_time = current_time; /* initialize for idle kicker */
#ifdef EXTSTORE
	c->io_wraplist = NULL;
	c->io_wrapleft = 0;
#endif

	c->item = 0;

	c->noreply = false;

#ifdef TLS
	if (ssl) {
		c->ssl = (SSL*)ssl;
		c->read = ssl_read;
		c->sendmsg = ssl_sendmsg;
		c->write = ssl_write;
		c->ssl_enabled = true;
		SSL_set_info_callback(c->ssl, ssl_callback);
	}
	else
#else
	// This must be NULL if TLS is not enabled.
	assert(ssl == NULL);
#endif
	{
// 		c->read = tcp_read;
// 		c->sendmsg = tcp_sendmsg;
// 		c->write = tcp_write;
	}

// 
// 	if (IS_UDP(transport)) {
// 		c->try_read_command = try_read_command_udp;
// 	}
// 	else {
// 		switch (c->protocol) {
// 		case ascii_prot:
// 			if (settings.auth_file == NULL) {
// 				c->authenticated = true;
// 				c->try_read_command = try_read_command_ascii;
// 			}
// 			else {
// 				c->authenticated = false;
// 				c->try_read_command = try_read_command_asciiauth;
// 			}
// 			break;
// 		case binary_prot:
// 			// binprot handles its own authentication via SASL parsing.
// 			c->authenticated = false;
// 			c->try_read_command = try_read_command_binary;
// 			break;
// 		case negotiating_prot:
// 			c->try_read_command = try_read_command_negotiate;
// 			break;
// 		}
// 	}

	event_assign(&c->event, base, sfd, event_flags, event_handler, (void *)c);
// 	event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
// 	event_base_set(base, &c->event);
	c->ev_flags = event_flags;

	if (event_add(&c->event, 0) == -1) {
		perror("event_add");
		return NULL;
	}

// 	STATS_LOCK();
// 	stats_state.curr_conns++;
// 	stats.total_conns++;
// 	STATS_UNLOCK();
// 
// 	MEMCACHED_CONN_ALLOCATE(c->sfd);

	return c;
}


void conn_listener::conn_free(conn *c)
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


void conn_listener::conn_close(conn *c)
{
	assert(c != NULL);

	/* delete the event, the socket and the conn */
	event_del(&c->event);

	if (settings.verbose > 1)
		fprintf(stderr, "<%d connection closed.\n", c->sfd);
// 
// 	conn_cleanup(c);
// 
// 	// force release of read buffer.
// 	if (c->thread) {
// 		c->rbytes = 0;
// 		rbuf_release(c);
// 	}
// 
// 	MEMCACHED_CONN_RELEASE(c->sfd);
// 	conn_set_state(c, conn_closed);
// #ifdef TLS
// 	if (c->ssl) {
// 		SSL_shutdown(c->ssl);
// 		SSL_free(c->ssl);
// 	}
// #endif
// 	close(c->sfd);
// 	pthread_mutex_lock(&conn_lock);
// 	allow_new_conns = true;
// 	pthread_mutex_unlock(&conn_lock);
// 
// 	STATS_LOCK();
// 	stats_state.curr_conns--;
// 	STATS_UNLOCK();

	return;
}

void conn_listener::event_handler(const int fd, const short which, void *arg)
{
	conn *c;

	c = (conn *)arg;
	assert(c != NULL);

	c->which = which;

	/* sanity */
	if (fd != c->sfd) {
		if (settings.verbose > 0)
			fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
		conn_close(c);
		return;
	}

	drive_machine(c);

	/* wait for next event */
	return;
}


void conn_listener::drive_machine(conn *c)
{
	bool stop = false;
	int sfd;
	socklen_t addrlen;
	struct sockaddr_storage addr;
	int nreqs = settings.reqs_per_event;
	int res;
	const char *str;
#ifdef HAVE_ACCEPT4
	static int  use_accept4 = 1;
#else
	static int  use_accept4 = 0;
#endif

	assert(c != NULL);

	while (!stop) {
		switch (c->state) {
		case conn_listening:
			addrlen = sizeof(addr);
#ifdef HAVE_ACCEPT4
			if (use_accept4) {
				sfd = accept4(c->sfd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
			}
			else {
				sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
			}
#else
			sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
#endif
			if (sfd == -1) {
				if (use_accept4 && errno == ENOSYS) {
					use_accept4 = 0;
					continue;
				}
				perror(use_accept4 ? "accept4()" : "accept()");
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/* these are transient, so don't log anything */
					stop = true;
				}
				else if (errno == EMFILE) {
					if (settings.verbose > 0)
						fprintf(stderr, "Too many open connections\n");
					//accept_new_conns(false);
					stop = true;
				}
				else {
					perror("accept()");
					stop = true;
				}
				break;
			}
			if (!use_accept4) {
// 				if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
// 					perror("setting O_NONBLOCK");
// 					close(sfd);
// 					break;
// 				}
			}

// 			bool reject;
// 			if (settings.maxconns_fast) {
// 				STATS_LOCK();
// 				reject = stats_state.curr_conns + stats_state.reserved_fds >= settings.maxconns - 1;
// 				if (reject) {
// 					stats.rejected_conns++;
// 				}
// 				STATS_UNLOCK();
// 			}
// 			else {
// 				reject = false;
// 			}
// 
// 			if (reject) {
// 				str = "ERROR Too many open connections\r\n";
// 				res = write(sfd, str, strlen(str));
// 				close(sfd);
// 			}
// 			else {
// 				void *ssl_v = NULL;
// #ifdef TLS
// 				SSL *ssl = NULL;
// 				if (c->ssl_enabled) {
// 					assert(IS_TCP(c->transport) && settings.ssl_enabled);
// 
// 					if (settings.ssl_ctx == NULL) {
// 						if (settings.verbose) {
// 							fprintf(stderr, "SSL context is not initialized\n");
// 						}
// 						close(sfd);
// 						break;
// 					}
// 					SSL_LOCK();
// 					ssl = SSL_new(settings.ssl_ctx);
// 					SSL_UNLOCK();
// 					if (ssl == NULL) {
// 						if (settings.verbose) {
// 							fprintf(stderr, "Failed to created the SSL object\n");
// 						}
// 						close(sfd);
// 						break;
// 					}
// 					SSL_set_fd(ssl, sfd);
// 					int ret = SSL_accept(ssl);
// 					if (ret < 0) {
// 						int err = SSL_get_error(ssl, ret);
// 						if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
// 							if (settings.verbose) {
// 								fprintf(stderr, "SSL connection failed with error code : %d : %s\n", err, strerror(errno));
// 							}
// 							SSL_free(ssl);
// 							close(sfd);
// 							break;
// 						}
// 					}
// 				}
// 				ssl_v = (void*)ssl;
// #endif

// 				dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
// 					READ_BUFFER_CACHED, c->transport, ssl_v);
			}

			stop = true;
			break;
	}

	return;
}

void conn_listener::dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size, enum network_transport transport, void *ssl)
{

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
#ifndef _WIN32
	if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
		fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("setting O_NONBLOCK");
		close(sfd);
		return -1;
	}
#else
	unsigned int nonblocking = -1;
	if (ioctlsocket(sfd, FIONBIO, (u_long*)&nonblocking) != 0) {
		perror("setting O_NONBLOCK");
		socket_destroy(sfd);
		return -1;
	}
#endif

	return sfd;
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
	struct addrinfo hints = { 0 };
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
	error = getaddrinfo("10.18.60.48", port_buf, &hints, &ai);
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
				socket_destroy(sfd);
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
				socket_destroy(sfd);
				freeaddrinfo(ai);
				return 1;
			}
			socket_destroy(sfd);
			continue;
		}
		else {
			success++;
			if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1) {
				perror("listen()");
				socket_destroy(sfd);
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

		if (IS_UDP(transport)) {
			int c;

			for (c = 0; c < settings.num_threads_per_udp; c++) {
				/* Allocate one UDP file descriptor per worker thread;
				 * this allows "stats conns" to separately list multiple
				 * parallel UDP requests in progress.
				 *
				 * The dispatch code round-robins new connection requests
				 * among threads, so this is guaranteed to assign one
				 * FD to each thread.
				 */
				int per_thread_fd;
				if (c == 0) {
					per_thread_fd = sfd;
				}
				else {
#ifndef _WIN32
					per_thread_fd = dup(sfd);
					if (per_thread_fd < 0) {
						perror("Failed to duplicate file descriptor");
						exit(EXIT_FAILURE);
					}
#endif
				}
				dispatch_conn_new(per_thread_fd, conn_read,
					EV_READ | EV_PERSIST,
					UDP_READ_BUFFER_SIZE, transport, NULL);
			}
		}
		else {
			if (!(listen_conn_add = conn_new(sfd, conn_listening,
				EV_READ | EV_PERSIST, 1,
				transport, main_base, NULL))) {
				fprintf(stderr, "failed to create listening connection\n");
				exit(EXIT_FAILURE);
			}
#ifdef TLS
			listen_conn_add->ssl_enabled = ssl_enabled;
#else
			assert(ssl_enabled == false);
#endif
			listen_conn_add->next = listen_conn;
			listen_conn = listen_conn_add;
		}
	}

	freeaddrinfo(ai);

	/* Return zero if we detected no errors in starting up connections */
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
#ifndef _WIN32 
		char *list = strdup(settings.inter);
#else
		char *list = _strdup(settings.inter);
#endif
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