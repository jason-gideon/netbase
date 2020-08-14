#pragma once

#include <mutex>

template <typename T>
class conn_queue {
public:
	conn_queue();
	~conn_queue() = default;

	void cq_init();
	T *cq_pop();
	void cq_push(T*item);

private:
	T* head;
	T* tail;
	std::mutex lock;
	//std::mutex cqi_freelist_lock;
	//static T *cqi_freelist;
};


template <typename T>
conn_queue<T>::conn_queue()
{
	cq_init();
}

template <typename T>
void conn_queue<T>::cq_init()
{
	head = nullptr;
	tail = nullptr;
}

/*
 * Adds an item to a connection queue.
 */
template <typename T>
void conn_queue<T>::cq_push(T* item) {
	item->next = NULL;

	std::lock_guard<std::mutex> guard(lock);
	if (NULL == this->tail)
		this->head = item;
	else
		this->tail->next = item;
	this->tail = item;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
template <typename T>
T * conn_queue<T>::cq_pop() {
	T *item;

	std::lock_guard<std::mutex> guard(lock);
	item = this->head;
	if (NULL != item) {
		this->head = item->next;
		if (NULL == this->head)
			this->tail = NULL;
	}

	return item;
}
