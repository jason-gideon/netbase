#pragma once

#include "netb.h"
#include "conn_factory.h"

namespace netb {

	class listener {
	public:
		listener();
    listener(conn_factory* factory);
	
		virtual ~listener();

    bool init();

    void loop();


  protected:
    int new_socket(struct addrinfo *ai);

    int server_socket(const char *interfaces,
      int port,
      enum network_transport transport,
      FILE *portnumber_file, bool ssl_enabled);

    int server_sockets(int port, enum network_transport transport,
      FILE *portnumber_file);


		void memcached_thread_init(int nthreads, void *arg);
		void setup_thread(LIBEVENT_THREAD *me);

	protected:

    static void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
      int read_buffer_size, enum network_transport transport, void *ssl);

		void wait_for_thread_registration(int nthreads);

		static void register_thread_initialized(void);


		/*
		 * Creates a worker thread.
		 */
		void create_worker(void *(*func)(void *), void *arg);

		/*
		 * Worker thread: main event loop
		 */
		static void *worker_libevent(void *arg);

		/*
		 * Processes an incoming "handle a new connection" item. This is called when
		 * input arrives on the libevent wakeup pipe.
		 */
		static void thread_libevent_process(int fd, short which, void *arg);

    virtual conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
      enum network_transport transport, struct event_base *base, void *ssl);


  protected:
    static enum transmit_result transmit(conn *c);

    static enum try_read_result try_read_network(conn *c);
    static enum try_read_result try_read_udp(conn *c);
    static int try_read_command(conn *c);

    static int ensure_iov_space(conn *c);
    static int add_iov(conn *c, const void *buf, int len);
    static int add_msghdr(conn *c);

    static bool update_event(conn *c, const int new_flags);

    static void reset_cmd_handler(conn *c);

    static void drive_machine(conn *c);

    static void event_handler(const int fd, const short which, void *arg);

    static void conn_close(conn *c);

    static void conn_cleanup(conn *c);

    static void conn_set_state(conn *c, enum conn_states state);


  protected:
    conn_factory* factory;

    static struct settings settings;
  
  protected:
		/* Connection lock around accepting new connections */
		std::mutex conn_lock;
	
		/* Lock for global stats */
		std::mutex  stats_lock;
	
		/* Lock to cause worker threads to hang up after being woken */
		std::mutex  worker_hang_lock;
	
		std::mutex  *item_locks;
		/* size of the item lock hash table */
		static uint32_t item_lock_count;
		unsigned int item_lock_hashpower;

		/*
		 * Number of worker threads that have finished setting themselves up.
		 */
		static int init_count;
		static std::mutex init_lock;
		static std::condition_variable init_cond;
	
	
		/*
		 * Each libevent instance has a wakeup pipe, which other threads
		 * can use to signal that they've put a new connection on its queue.
		 */
		static LIBEVENT_THREAD *threads;
	};
}

