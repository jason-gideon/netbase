#include "thread.h"

namespace netb {
	thread::thread(int nthreads) {

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
		for (int i = 0; i < nthreads; i++) {
			LIBEVENT_THREAD thrd;
			int fds[2];
			if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
				perror("Can't create notify pipe");
				exit(1);
			}

			thrd.notify_receive_fd = fds[0];
			thrd.notify_send_fd = fds[1];
#ifdef EXTSTORE
			threads[i].storage = arg;
#endif
			setup_thread(&threads[i]);
			/* Reserve three fds for the libevent base, and two for the pipe */
			//stats_state.reserved_fds += 5;
		}
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
		
		//deprecated
		/*event_set(&me->notify_event, me->notify_receive_fd,
			EV_READ | EV_PERSIST, thread_libevent_process, me);
		event_base_set(me->base, &me->notify_event);*/

		if (event_add(&me->notify_event, 0) == -1) {
			fprintf(stderr, "Can't monitor libevent notify pipe\n");
			exit(1);
		}
		
		me->new_conn_queue = std::make_unique<conn_queue<CQ_ITEM>>();
		if (me->new_conn_queue.get() == nullptr) {  //??
			perror("Failed to allocate memory for connection queue");
			exit(EXIT_FAILURE);
		}


		/*me->new_conn_queue = (struct conn_queue *)malloc(sizeof(struct conn_queue));
		if (me->new_conn_queue == NULL) {
			perror("Failed to allocate memory for connection queue");
			exit(EXIT_FAILURE);
		}*/
// 		cq_init(me->new_conn_queue);
// 
// 		if (pthread_mutex_init(&me->stats.mutex, NULL) != 0) {
// 			perror("Failed to initialize mutex");
// 			exit(EXIT_FAILURE);
// 		}
// 
// 		me->resp_cache = cache_create("resp", sizeof(mc_resp), sizeof(char *), NULL, NULL);
// 		if (me->resp_cache == NULL) {
// 			fprintf(stderr, "Failed to create response cache\n");
// 			exit(EXIT_FAILURE);
// 		}
// 		// Note: we were cleanly passing in num_threads before, but this now
// 		// relies on settings globals too much.
// 		if (settings.resp_obj_mem_limit) {
// 			int limit = settings.resp_obj_mem_limit / settings.num_threads;
// 			if (limit < sizeof(mc_resp)) {
// 				limit = 1;
// 			}
// 			else {
// 				limit = limit / sizeof(mc_resp);
// 			}
// 			cache_set_limit(me->resp_cache, limit);
// 		}
// 
// 		me->rbuf_cache = cache_create("rbuf", READ_BUFFER_SIZE, sizeof(char *), NULL, NULL);
// 		if (me->rbuf_cache == NULL) {
// 			fprintf(stderr, "Failed to create read buffer cache\n");
// 			exit(EXIT_FAILURE);
// 		}
// 		if (settings.read_buf_mem_limit) {
// 			int limit = settings.read_buf_mem_limit / settings.num_threads;
// 			if (limit < READ_BUFFER_SIZE) {
// 				limit = 1;
// 			}
// 			else {
// 				limit = limit / READ_BUFFER_SIZE;
// 			}
// 			cache_set_limit(me->rbuf_cache, limit);
// 		}

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

	void thread::thread_libevent_process(int fd, short which, void *arg)
	{

	}

}
