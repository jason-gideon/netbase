#include "conn_queue.h"


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

template <typename T>
void conn_queue<T>::cqi_free(T *item)
{
	std::lock_guard guard(cqi_freelist_lock);
	item->next = cqi_freelist;
	cqi_freelist = item;
}

template <typename T>
T * conn_queue<T>::cqi_new(void)
{
	T *item = nullptr;

	{
		std::lock_guard guard(cqi_freelist_lock);
		if (cqi_freelist) {
			item = cqi_freelist;
			cqi_freelist = item->next;
		}
	}

	if (nullptr == item) {
		int i;

		/* Allocate a bunch of items at once to reduce fragmentation */
		item = malloc(sizeof(T) * ITEMS_PER_ALLOC);
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
			std::lock_guard guard(cqi_freelist_lock);
			item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
			cqi_freelist = &item[1];
		}

	}

	return item;
}

/*
 * Adds an item to a connection queue.
 */
template <typename T>
void conn_queue<T>::cq_push(T* item) {
	item->next = NULL;

	std::lock_guard guard(lock);
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

	std::lock_guard guard(lock);
	item = this->head;
	if (NULL != item) {
		this->head = item->next;
		if (NULL == this->head)
			this->tail = NULL;
	}

	return item;
}


