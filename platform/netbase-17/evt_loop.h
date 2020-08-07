#pragma once


#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>

#include "task_base.h"
#include "evt_watcher.h"


namespace netb {
  class pipe_watcher;
  class evt_loop : public task_base {
  public:
    typedef std::function<void()> Functor;

    evt_loop();


  private:
    void init();

    void setup_pipe_watcher();

    void worker_libevent();
  private:
    struct event_base* evbase_;

    std::thread::id tid_;
    std::shared_ptr<pipe_watcher> watcher_;

    std::mutex mutex_;
    std::vector<Functor>* pending_functors_; // @Guarded By mutex_
  };

}


