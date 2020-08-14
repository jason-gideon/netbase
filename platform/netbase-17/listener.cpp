#include "listener.h"
#include "cqi.h"
#include "util.h"

namespace netb {



  static int max_fds;

  static bool stop_main_loop;
  static conn *listen_conn;
  static struct event_base *main_base;



  int listener::init_count = 0;
  std::mutex listener::init_lock;
  std::condition_variable listener::init_cond;

  LIBEVENT_THREAD * listener::threads;

  struct settings listener::settings;



  /**
 * Convert a state name to a human readable form.
 */
  static const char *state_text(enum conn_states state) {
    const char* const statenames[] = { "conn_listening",
                                       "conn_new_cmd",
                                       "conn_waiting",
                                       "conn_read",
                                       "conn_parse_cmd",
                                       "conn_write",
                                       "conn_nread",
                                       "conn_swallow",
                                       "conn_closing",
                                       "conn_mwrite",
                                       "conn_closed",
                                       "conn_watch" };
    return statenames[state];
  }

  listener::listener() {

  }

  listener::listener(conn_factory* factory)
    : factory(factory)
  {

  }

  listener::~listener()
  {

  }

  bool listener::init()
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


    memcached_thread_init(4, this);



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

    return false;
  }

  void listener::loop()
  {
    /* enter the event loop */
    while (!stop_main_loop) {
      if (event_base_loop(main_base, EVLOOP_ONCE) != 0) {
        //retval = EXIT_FAILURE;
        break;
      }
    }
  }


  int listener::new_socket(struct addrinfo *ai)
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

  int listener::server_socket(const char *interfaces, int port, enum network_transport transport, FILE *portnumber_file, bool ssl_enabled)
  {
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
    //error = getaddrinfo("10.18.60.48", port_buf, &hints, &ai);
    error = getaddrinfo("127.0.0.1", port_buf, &hints, &ai);
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


  int listener::server_sockets(int port, enum network_transport transport, FILE *portnumber_file) {
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

  /*
   * Initializes the thread subsystem, creating various worker threads.
   *
   * nthreads  Number of worker event handler threads to spawn
   */
  void listener::memcached_thread_init(int nthreads, void *arg) {

    threads = (LIBEVENT_THREAD*)calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (!threads) {
      perror("Can't allocate thread descriptors");
      exit(1);
    }

    for (int i = 0; i < nthreads; i++) {
      int fds[2];
      if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        perror("Can't create notify pipe");
        exit(1);
      }

      threads[i].notify_receive_fd = fds[0];
      threads[i].notify_send_fd = fds[1];
#ifdef EXTSTORE
      threads[i].storage = arg;
#endif
      setup_thread(&threads[i]);
      /* Reserve three fds for the libevent base, and two for the pipe */
      //stats_state.reserved_fds += 5;
    }

    /* Create threads after we've done all the libevent setup. */
    for (int i = 0; i < nthreads; i++) {
      create_worker(worker_libevent, &threads[i]);
    }

    /* Wait for all the threads to set themselves up before returning. */
    wait_for_thread_registration(nthreads);
  }

  void listener::setup_thread(LIBEVENT_THREAD *me) {
#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000101
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    me->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
#else
    me->base = event_init();
#endif

    if (!me->base) {
      fprintf(stderr, "Can't allocate event base\n");
      exit(1);
    }

    /* Listen for notifications from other threads */
    event_assign(&me->notify_event, me->base, me->notify_receive_fd,
      EV_READ | EV_PERSIST, thread_libevent_process, me);

    if (event_add(&me->notify_event, 0) == -1) {
      fprintf(stderr, "Can't monitor libevent notify pipe\n");
      exit(1);
    }

    me->new_conn_queue = std::make_shared<conn_queue<CQ_ITEM>>();
    if (me->new_conn_queue == nullptr) {  //??
      perror("Failed to allocate memory for connection queue");
      exit(EXIT_FAILURE);
    }

    me->user = this;

#ifdef EXTSTORE
    me->io_cache = cache_create("io", sizeof(io_wrap), sizeof(char*), NULL, NULL);
    if (me->io_cache == NULL) {
      fprintf(stderr, "Failed to create IO object cache\n");
      exit(EXIT_FAILURE);
    }
#endif
#ifdef TLS
    if (settings.ssl_enabled) {
      me->ssl_wbuf = (char *)malloc((size_t)settings.ssl_wbuf_size);
      if (me->ssl_wbuf == NULL) {
        fprintf(stderr, "Failed to allocate the SSL write buffer\n");
        exit(EXIT_FAILURE);
      }
    }
#endif
  }


  /* Which thread we assigned a connection to most recently. */
  static int last_thread = -1;
  void listener::dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size, enum network_transport transport, void *ssl)
  {
    CQ_ITEM *item = cqi_new();
    char buf[1];
    if (item == NULL) {
      socket_destroy(sfd);
      /* given that malloc failed this may also fail, but let's try */
      fprintf(stderr, "Failed to allocate memory for connection object\n");
      return;
    }

    int tid = (last_thread + 1) % 4;

    LIBEVENT_THREAD *listener = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;
    item->mode = queue_new_conn;
    item->ssl = ssl;

    listener->new_conn_queue->cq_push(item);

    buf[0] = 'c';
    if (socket_write(listener->notify_send_fd, buf, 1) != 1) {
      perror("Writing to thread notify pipe");
    }
  }

  void listener::wait_for_thread_registration(int nthreads)
  {
    std::unique_lock<std::mutex> lck(init_lock);
    while (init_count < nthreads) init_cond.wait(lck);
  }

  void listener::register_thread_initialized(void)
  {
    {
      std::unique_lock<std::mutex> lck(init_lock);
      init_count++;
      init_cond.notify_one();
    }

    /* Force worker threads to pile up if someone wants us to */
    //pthread_mutex_lock(&worker_hang_lock);
    //pthread_mutex_unlock(&worker_hang_lock);
}

  void listener::create_worker(void *(*func)(void *), void *arg)
  {
    std::thread* worker = new std::thread(func, arg);
    ((LIBEVENT_THREAD*)arg)->thread_id = worker->get_id();
  }

  void * listener::worker_libevent(void *arg)
  {
    LIBEVENT_THREAD *me = (LIBEVENT_THREAD*)arg;

    /* Any per-thread setup can happen here; memcached_thread_init() will block until
     * all threads have finished initializing.
     */
    register_thread_initialized();

    event_base_loop(me->base, 0);

    // same mechanism used to watch for all threads exiting.
    register_thread_initialized();

    event_base_free(me->base);
    return NULL;
  }

  void listener::thread_libevent_process(int fd, short which, void *arg)
  {
    LIBEVENT_THREAD *me = (LIBEVENT_THREAD*)arg;
    listener* svr = (listener*)me->user;
    CQ_ITEM *item = NULL;
    char buf[1];
    conn *c;
    unsigned int fd_from_pipe;

    //if (read(fd, buf, 1) != 1) {
    if (socket_read(fd, buf, sizeof buf) != 1) {
      //if (settings.verbose > 0)
      fprintf(stderr, "Can't read from libevent pipe\n");
      return;
    }


    switch (buf[0]) {
    case 'c':
      item = me->new_conn_queue->cq_pop();

      if (NULL == item) {
        break;
      }
      switch (item->mode) {
      case queue_new_conn:
        c = svr->conn_new(item->sfd, item->init_state, item->event_flags,
          item->read_buffer_size, item->transport,
          me->base, item->ssl);
        if (c == NULL) {
          if (IS_UDP(item->transport)) {
            fprintf(stderr, "Can't listen for events on UDP socket\n");
            exit(1);
          }
          else {
            //if (settings.verbose > 0) 
              fprintf(stderr, "Can't listen for events on fd %d\n", item->sfd);
            
#ifdef TLS
            if (item->ssl) {
              SSL_shutdown(item->ssl);
              SSL_free(item->ssl);
            }
#endif
            socket_destroy(item->sfd);
          }
        }
        else {
          c->thread = me;
#ifdef TLS
          if (settings.ssl_enabled && c->ssl != NULL) {
            assert(c->thread && c->thread->ssl_wbuf);
            c->ssl_wbuf = c->thread->ssl_wbuf;
          }
#endif
        }
        break;
      }
      cqi_free(item);
      break;
      /* we were told to pause and report in */
    case 'p':
      register_thread_initialized();
      break;
      /* a client socket timed out */
    case 't':
      if (socket_read(fd, (char*)&fd_from_pipe, sizeof(fd_from_pipe)) != sizeof(fd_from_pipe)) {
        //if (settings.verbose > 0)
          fprintf(stderr, "Can't read timeout fd from libevent pipe\n");
        return;
      }
      //conn_close_idle(conns[fd_from_pipe]);
      break;
      /* a side thread redispatched a client connection */
    case 'r':
      if (socket_read(fd, (char*)&fd_from_pipe, sizeof(fd_from_pipe)) != sizeof(fd_from_pipe)) {
        //if (settings.verbose > 0)
          fprintf(stderr, "Can't read redispatch fd from libevent pipe\n");
        return;
      }
      //conn_worker_readd(conns[fd_from_pipe]);
      break;
      /* asked to stop */
    case 's':
      event_base_loopexit(me->base, NULL);
      break;
    }
  }

  conn * listener::conn_new(const int sfd, enum conn_states init_state,
    const int event_flags,
    const int read_buffer_size, enum network_transport transport,
    struct event_base *base, void *ssl) {
    conn *c;

    assert(sfd >= 0 && sfd < factory->maxfd());
    c = factory->conn_new(sfd);

    if (NULL == c) {
      fprintf(stderr, "Failed to allocate connection object\n");
      return NULL;
    }

    //MEMCACHED_CONN_CREATE(c);
    c->rbuf = c->wbuf = 0;
    //c->ilist = 0;
    c->suffixlist = 0;
    c->iov = 0;
    c->msglist = 0;
    c->hdrbuf = 0;

    c->rsize = read_buffer_size;
    c->wsize = DATA_BUFFER_SIZE;
    c->isize = ITEM_LIST_INITIAL;
    c->suffixsize = SUFFIX_LIST_INITIAL;
    c->iovsize = IOV_LIST_INITIAL;
    c->msgsize = MSG_LIST_INITIAL;
    c->hdrsize = 0;

    c->rbuf = (char *)malloc((size_t)c->rsize);
    c->wbuf = (char *)malloc((size_t)c->wsize);
    //c->ilist = (item **)malloc(sizeof(item *) * c->isize);
    c->suffixlist = (char **)malloc(sizeof(char *) * c->suffixsize);
    c->iov = (struct iovec *)malloc(sizeof(struct iovec) * c->iovsize);
    c->msglist = (struct msghdr *)malloc(sizeof(struct msghdr) * c->msgsize);

    if (c->rbuf == 0 || c->wbuf == 0 || /*c->ilist == 0 || */c->iov == 0 ||
      c->msglist == 0 || c->suffixlist == 0) {
      factory->conn_free(c);
      //     STATS_LOCK();
      //     stats.malloc_fails++;
      //     STATS_UNLOCK();
      fprintf(stderr, "Failed to allocate buffers for connection\n");
      return NULL;
    }




    c->read = NULL;
    c->sendmsg = NULL;
    c->write = NULL;
    //c->rbuf = NULL;

//     c->rsize = read_buffer_size;
// 
//     // UDP connections use a persistent static buffer.
//     if (c->rsize) {
//       c->rbuf = (char *)malloc((size_t)c->rsize);
//     }

    if (c->rsize && c->rbuf == NULL) {
      factory->conn_free(c);
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



  void listener::event_handler(const int fd, const short which, void *arg)
  {
    conn *c;

    c = (conn *)arg;
    assert(c != NULL);

    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
      //if (settings.verbose > 0)
      fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
      conn_close(c);
      return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
  }

  void listener::conn_close(conn *c)
  {
    assert(c != NULL);

    /* delete the event, the socket and the conn */
    event_del(&c->event);

    //if (settings.verbose > 1)
    fprintf(stderr, "<%d connection closed.\n", c->sfd);

    conn_cleanup(c);

    // force release of read buffer.
    if (c->thread) {
      c->rbytes = 0;
      //rbuf_release(c);
    }

    //MEMCACHED_CONN_RELEASE(c->sfd);
    conn_set_state(c, conn_closed);
#ifdef TLS
    if (c->ssl) {
      SSL_shutdown(c->ssl);
      SSL_free(c->ssl);
    }
#endif
    socket_destroy(c->sfd);
    //   pthread_mutex_lock(&conn_lock);
    //   allow_new_conns = true;
    //   pthread_mutex_unlock(&conn_lock);

    //   STATS_LOCK();
    //   stats_state.curr_conns--;
    //   STATS_UNLOCK();

    return;
  }

  void listener::conn_cleanup(conn *c)
  {
    assert(c != NULL);

    //conn_release_items(c);

  //   if (c->sasl_conn) {
  //     assert(settings.sasl);
  //     sasl_dispose(&c->sasl_conn);
  //     c->sasl_conn = NULL;
  //   }

    if (IS_UDP(c->transport)) {
      conn_set_state(c, conn_read);
    }
  }

  void listener::conn_set_state(conn *c, enum conn_states state)
  {
    assert(c != NULL);
    assert(state >= conn_listening && state < conn_max_state);

    if (state != c->state) {
      //if (settings.verbose > 2) {
      fprintf(stderr, "%d: going from %s to %s\n",
        c->sfd, state_text(c->state),
        state_text(state));
      //}

      if (state == conn_write || state == conn_mwrite) {
        //MEMCACHED_PROCESS_COMMAND_END(c->sfd, c->wbuf, c->wbytes);
      }
      c->state = state;
    }
  }

  //redisÔõÃ´²Ù×÷µÄ?
  void listener::drive_machine(conn *c)
  {
    bool stop = false;
    int sfd;
    socklen_t addrlen;
    struct sockaddr_storage addr;
    int nreqs = 3;
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
      case conn_listening: {
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
            //if (settings.verbose > 0)
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
          //         if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
          //           perror("setting O_NONBLOCK");
          //           close(sfd);
          //           break;
          //         }
        }

        bool reject = false;
        //      if (settings.maxconns_fast) {
        //         STATS_LOCK();
        //         reject = stats_state.curr_conns + stats_state.reserved_fds >= settings.maxconns - 1;
        //         if (reject) {
        //           stats.rejected_conns++;
        //         }
        //         STATS_UNLOCK();
        //       }
        //       else {
        //         reject = false;
        //       }

        if (reject) {
          str = "ERROR Too many open connections\r\n";
          res = socket_write(sfd, str, strlen(str));
          socket_destroy(sfd);
        }
        else {
          void *ssl_v = NULL;
#ifdef TLS
          SSL *ssl = NULL;
          if (c->ssl_enabled) {
            assert(IS_TCP(c->transport) && settings.ssl_enabled);

            if (settings.ssl_ctx == NULL) {
              if (settings.verbose) {
                fprintf(stderr, "SSL context is not initialized\n");
              }
              close(sfd);
              break;
            }
            SSL_LOCK();
            ssl = SSL_new(settings.ssl_ctx);
            SSL_UNLOCK();
            if (ssl == NULL) {
              if (settings.verbose) {
                fprintf(stderr, "Failed to created the SSL object\n");
              }
              close(sfd);
              break;
            }
            SSL_set_fd(ssl, sfd);
            int ret = SSL_accept(ssl);
            if (ret < 0) {
              int err = SSL_get_error(ssl, ret);
              if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                if (settings.verbose) {
                  fprintf(stderr, "SSL connection failed with error code : %d : %s\n", err, strerror(errno));
                }
                SSL_free(ssl);
                close(sfd);
                break;
              }
            }
          }
          ssl_v = (void*)ssl;
#endif

          dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
            DATA_BUFFER_SIZE, c->transport, ssl_v);
        }

        stop = true;
        break;
      }
      case conn_waiting:
        fprintf(stderr, "conn_waiting\n");
        if (!update_event(c, EV_READ | EV_PERSIST)) {
          // if (settings.verbose > 0)
          fprintf(stderr, "Couldn't update event\n");
          conn_set_state(c, conn_closing);
          break;
        }

        conn_set_state(c, conn_read);
        stop = true;
        break;

      case conn_read:
        fprintf(stderr, "conn_read\n");
        res = IS_UDP(c->transport) ? try_read_udp(c) : try_read_network(c);

        switch (res) {
        case READ_NO_DATA_RECEIVED:
          conn_set_state(c, conn_waiting);
          break;
        case READ_DATA_RECEIVED:
          conn_set_state(c, conn_parse_cmd);
          break;
        case READ_ERROR:
          conn_set_state(c, conn_closing);
          break;
        case READ_MEMORY_ERROR: /* Failed to allocate more memory */
            /* State already set by try_read_network */
          break;
        }
        break;

      case conn_parse_cmd:
        fprintf(stderr, "conn_parse_cmd\n");
        break;

      case conn_new_cmd:
        fprintf(stderr, "conn_new_cmd\n");
        /* Only process nreqs at a time to avoid starving other
                       connections */

        --nreqs;
        if (nreqs >= 0) {
          reset_cmd_handler(c);
        }
        //       else if (c->resp_head) {
        //         // flush response pipe on yield.
        //         conn_set_state(c, conn_mwrite);
        //       }
        else {
          //         pthread_mutex_lock(&c->thread->stats.mutex);
          //         c->thread->stats.conn_yields++;
          //         pthread_mutex_unlock(&c->thread->stats.mutex);
          if (c->rbytes > 0) {
            /* We have already read in data into the input buffer,
               so libevent will most likely not signal read events
               on the socket (unless more data is available. As a
               hack we should just put in a request to write data,
               because that should be possible ;-)
            */
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
              //if (settings.verbose > 0)
              fprintf(stderr, "Couldn't update event\n");
              conn_set_state(c, conn_closing);
              break;
            }
          }
          stop = true;
        }
        break;

      case conn_nread:
        fprintf(stderr, "conn_nread\n");
        break;

      case conn_swallow:
        fprintf(stderr, "conn_swallow\n");
        break;

      case conn_write:
      case conn_mwrite:
        fprintf(stderr, "conn_mwrite\n");
        break;
      case conn_closing:
        fprintf(stderr, "conn_closing\n");
        if (IS_UDP(c->transport))
          conn_cleanup(c);
        else
          conn_close(c);
        stop = true;
        break;

      case conn_closed:
        /* This only happens if dormando is an idiot. */
        fprintf(stderr, "conn_closed\n");
        abort();
        break;

      case conn_watch:
        fprintf(stderr, "conn_watch\n");
        /* We handed off our connection to the logger thread. */
        stop = true;
        break;
      case conn_max_state:
        fprintf(stderr, "conn_max_state\n");
        assert(false);
        break;
      }
    }
  }

  void listener::reset_cmd_handler(conn *c)
  {
    c->cmd = -1;
    //c->substate = bin_no_state;
    if (c->item != NULL) {
      // TODO: Any other way to get here?
      // SASL auth was mistakenly using it. Nothing else should?
      //item_remove(c->item);
      c->item = NULL;
    }
    if (c->rbytes > 0) {
      conn_set_state(c, conn_parse_cmd);
    }
    //   else if (c->resp_head) {
    //     conn_set_state(c, conn_mwrite);
    //   }
    else {
      conn_set_state(c, conn_waiting);
    }
  }

  bool listener::update_event(conn *c, const int new_flags)
  {
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
      return true;
    if (event_del(&c->event) == -1) return false;

    event_assign(&c->event, base, c->sfd, new_flags, event_handler, (void *)c);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
  }

  enum try_read_result listener::try_read_network(conn *c) {
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
    int res;
    int num_allocs = 0;
    assert(c != NULL);

    if (c->rcurr != c->rbuf) {
      if (c->rbytes != 0) /* otherwise there's nothing to copy */
        memmove(c->rbuf, c->rcurr, c->rbytes);
      c->rcurr = c->rbuf;
    }

    while (1) {
      if (c->rbytes >= c->rsize) {
        if (num_allocs == 4) {
          return gotdata;
        }
        ++num_allocs;
        char *new_rbuf = (char*)realloc(c->rbuf, c->rsize * 2);
        if (!new_rbuf) {
//           STATS_LOCK();
//           stats.malloc_fails++;
//           STATS_UNLOCK();
          if (settings.verbose > 0) {
            fprintf(stderr, "Couldn't realloc input buffer\n");
          }
          c->rbytes = 0; /* ignore what we read */

          //return err to server
//          out_of_memory(c, "SERVER_ERROR out of memory reading request");
//          c->write_and_go = conn_closing;
          return READ_MEMORY_ERROR;
        }
        c->rcurr = c->rbuf = new_rbuf;
        c->rsize *= 2;
      }

      int avail = c->rsize - c->rbytes;
      res = socket_read(c->sfd, c->rbuf + c->rbytes, avail);
      if (res > 0) {
//         pthread_mutex_lock(&c->thread->stats.mutex);
//         c->thread->stats.bytes_read += res;
//         pthread_mutex_unlock(&c->thread->stats.mutex);
        gotdata = READ_DATA_RECEIVED;
        c->rbytes += res;
        if (res == avail) {
          continue;
        }
        else {
          break;
        }
      }
      if (res == 0) {
        return READ_ERROR;
      }
      if (res == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        return READ_ERROR;
      }
    }
    return gotdata;
  }

  enum try_read_result listener::try_read_udp(conn *c) {
    int res;

    assert(c != NULL);

    c->request_addr_size = sizeof(c->request_addr);
    res = recvfrom(c->sfd, c->rbuf, c->rsize,
      0, (struct sockaddr *)&c->request_addr,
      &c->request_addr_size);
    if (res > 8) {
      unsigned char *buf = (unsigned char *)c->rbuf;
//       pthread_mutex_lock(&c->thread->stats.mutex);
//       c->thread->stats.bytes_read += res;
//       pthread_mutex_unlock(&c->thread->stats.mutex);

      /* Beginning of UDP packet is the request ID; save it. */
      c->request_id = buf[0] * 256 + buf[1];

      /* If this is a multi-packet request, drop it. */
      if (buf[4] != 0 || buf[5] != 1) {
        //out_string(c, "SERVER_ERROR multi-packet request not supported");
        return READ_NO_DATA_RECEIVED;
      }

      /* Don't care about any of the rest of the header. */
      res -= 8;
      memmove(c->rbuf, c->rbuf + 8, res);

      c->rbytes = res;
      c->rcurr = c->rbuf;
      return READ_DATA_RECEIVED;
    }
    return READ_NO_DATA_RECEIVED;
  }

}
