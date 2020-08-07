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
	
	protected:
		static void thread_libevent_process(int fd, short which, void *arg);
	protected:
		/* Connection lock around accepting new connections */
		std::mutex conn_lock;
	
		/* Lock for global stats */
		std::mutex  stats_lock;
	
		/* Lock to cause worker threads to hang up after being woken */
		std::mutex  worker_hang_lock;
	
		/* Free list of CQ_ITEM structs */
// 		static CQ_ITEM *cqi_freelist;
// 		std::mutex  cqi_freelist_lock;
	
		std::mutex  *item_locks;
		/* size of the item lock hash table */
		static uint32_t item_lock_count;
		unsigned int item_lock_hashpower;
	
	
		/*
		 * Each libevent instance has a wakeup pipe, which other threads
		 * can use to signal that they've put a new connection on its queue.
		 */
		//static LIBEVENT_THREAD *threads;
		std::vector<LIBEVENT_THREAD> threads;
	};
}

