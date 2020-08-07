#pragma once

#include <mutex>

#define ITEMS_PER_ALLOC 64


template <typename T>
class conn_queue {
public:
	conn_queue();
	~conn_queue() = default;

	void cq_init();
	T *cq_pop();
	void cq_push(T*item);

	T *cqi_new(void);

	void cqi_free(T *item);
private:
	T* head;
	T* tail;
	std::mutex lock;
	std::mutex cqi_freelist_lock;
	static T *cqi_freelist;
};
