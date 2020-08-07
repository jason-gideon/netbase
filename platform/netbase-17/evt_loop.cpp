#include "evt_loop.h"

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>

namespace netb {
  
  evt_loop::evt_loop()
  {
#if LIBEVENT_VERSION_NUMBER >= 0x02001500
    struct event_config* cfg = event_config_new();
    if (cfg) {
      // Does not cache time to get a preciser timer
      event_config_set_flag(cfg, EVENT_BASE_FLAG_NO_CACHE_TIME);
      evbase_ = (struct event_base*)event_base_new_with_config(cfg);
      event_config_free(cfg);
    }
#else
    evbase_ = event_base_new();
#endif
  }

  void evt_loop::init()
  {

  }

  void evt_loop::setup_pipe_watcher()
  {
    if (watcher_) {
      watcher_.reset(new pipe_watcher(this, std::bind(&evt_loop::worker_libevent, this)));
    }
  }

  void evt_loop::worker_libevent()
  {

  }

}