#include "cqi.h"

/* Free list of CQ_ITEM structs */
static CQ_ITEM *cqi_freelist = NULL;
static std::mutex  cqi_freelist_lock;

CQ_ITEM * cqi_new(void)
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

void cqi_free(CQ_ITEM *item)
{
  std::lock_guard<std::mutex> guard(cqi_freelist_lock);
  item->next = cqi_freelist;
  cqi_freelist = item;
}
