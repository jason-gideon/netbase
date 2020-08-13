#include "thread.h"

namespace netb {

  int thread::init_count = 0;
  std::mutex thread::init_lock;
  std::condition_variable thread::init_cond;

  CQ_ITEM * thread::cqi_freelist;
  std::mutex thread::cqi_freelist_lock;

  LIBEVENT_THREAD * thread::threads;

  thread::thread() {

  }

  thread::~thread()
  {

  }

  /*
   * Initializes the thread subsystem, creating various worker threads.
   *
   * nthreads  Number of worker event handler threads to spawn
   */
  void thread::memcached_thread_init(int nthreads, void *arg) {

    cqi_freelist = NULL;

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

  void thread::setup_thread(LIBEVENT_THREAD *me) {
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

    me->listener = this;

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
  void thread::dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size, enum network_transport transport, void *ssl)
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

    LIBEVENT_THREAD *thread = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;
    item->mode = queue_new_conn;
    item->ssl = ssl;

    thread->new_conn_queue->cq_push(item);

    buf[0] = 'c';
    if (socket_write(thread->notify_send_fd, buf, 1) != 1) {
      perror("Writing to thread notify pipe");
    }
  }

  void thread::wait_for_thread_registration(int nthreads)
  {
    std::unique_lock<std::mutex> lck(init_lock);
    while (init_count < nthreads) init_cond.wait(lck);
  }

  void thread::register_thread_initialized(void)
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

  void thread::create_worker(void *(*func)(void *), void *arg)
  {
    std::thread* worker = new std::thread(func, arg);
    ((LIBEVENT_THREAD*)arg)->thread_id = worker->get_id();
  }

  void * thread::worker_libevent(void *arg)
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

  void thread::thread_libevent_process(int fd, short which, void *arg)
  {
    LIBEVENT_THREAD *me = (LIBEVENT_THREAD*)arg;
    thread* listener = (thread*)me->listener;
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
        c = listener->conn_new(item->sfd, item->init_state, item->event_flags,
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


  CQ_ITEM * thread::cqi_new(void)
  {
    CQ_ITEM *item = nullptr;

    {
      std::lock_guard<std::mutex> guard(cqi_freelist_lock);
      if (cqi_freelist) {
        item = cqi_freelist;
        cqi_freelist = item->next;
      }
    }

    if (nullptr == item) {
      int i;

      /* Allocate a bunch of items at once to reduce fragmentation */
      item = (CQ_ITEM*)malloc(sizeof(CQ_ITEM) * ITEMS_PER_ALLOC);
      if (nullptr == item) {
        // 			STATS_LOCK();
        // 			stats.malloc_fails++;
        // 			STATS_UNLOCK();
        return nullptr;
      }

      /*
       * Link together all the new items except the first one
       * (which we'll return to the caller) for placement on
       * the freelist.
       */
      for (i = 2; i < ITEMS_PER_ALLOC; i++)
        item[i - 1].next = &item[i];

      {
        std::lock_guard<std::mutex> guard(cqi_freelist_lock);
        item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
        cqi_freelist = &item[1];
      }

    }

    return item;
  }

  void thread::cqi_free(CQ_ITEM *item)
  {
    std::lock_guard<std::mutex> guard(cqi_freelist_lock);
    item->next = cqi_freelist;
    cqi_freelist = item;
  }

  conn * thread::conn_new(const int sfd, enum conn_states init_state,
    const int event_flags,
    const int read_buffer_size, enum network_transport transport,
    struct event_base *base, void *ssl) {
    return nullptr;
  }


}
