#pragma once

#include "netb.h"


//#define ITEMS_PER_ALLOC 64


//
///* A connection queue. */
//typedef struct conn_queue CQ;
//struct conn_queue {
//	CQ_ITEM *head;
//	CQ_ITEM *tail;
//	std::mutex lock;
//};
//////////////////////////////////////////////////////////////////////////


//actually is singleton
namespace netb {



	class thread {
	public:
		thread(int nthreads);
	
		~thread();

		void memcached_thread_init(int nthreads, void *arg);
		void setup_thread(LIBEVENT_THREAD *me);
	
		void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
			int read_buffer_size, enum network_transport transport, void *ssl);

	protected:
		void wait_for_thread_registration(int nthreads);

		static void register_thread_initialized(void);


		/*
		 * Creates a worker thread.
		 */
		static void create_worker(void *(*func)(void *), void *arg);

		/*
		 * Worker thread: main event loop
		 */
		static void *worker_libevent(void *arg);

		/*
		 * Processes an incoming "handle a new connection" item. This is called when
		 * input arrives on the libevent wakeup pipe.
		 */
		static void thread_libevent_process(int fd, short which, void *arg);


		static CQ_ITEM *cqi_new(void);

		static void cqi_free(CQ_ITEM *item);
	protected:
		/* Connection lock around accepting new connections */
		std::mutex conn_lock;
	
		/* Lock for global stats */
		std::mutex  stats_lock;
	
		/* Lock to cause worker threads to hang up after being woken */
		std::mutex  worker_hang_lock;
	
		/* Free list of CQ_ITEM structs */
		static CQ_ITEM *cqi_freelist;
		static std::mutex  cqi_freelist_lock;
	
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
		//static LIBEVENT_THREAD *threads;
		std::vector<LIBEVENT_THREAD> threads;
	};
}

