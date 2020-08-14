#pragma once

#include "netb.h"

#define ITEMS_PER_ALLOC 64


CQ_ITEM *cqi_new(void);

void cqi_free(CQ_ITEM *item);