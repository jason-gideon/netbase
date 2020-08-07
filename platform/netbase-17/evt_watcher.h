#pragma once

#include <functional>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include "evt_loop.h"

namespace netb {
  class evt_loop;
  class evt_watcher {
  public:
    typedef std::function<void()> handler;

    virtual ~evt_watcher() = 0;

    bool init();

  protected:
    evt_watcher(struct event_base* base, const handler & cb);


    bool watch();
    void close();
    void free_evt();




    virtual bool on_init() = 0;
    virtual void on_close() = 0;


  protected:
    struct event* notify_event_;
    struct event_base* evbase_;
    bool attached_;
    handler cb_libevent_process_;
    handler cancel_callback_;
  };


  class pipe_watcher : public evt_watcher {
  public:
    pipe_watcher(evt_loop* loop, const handler& cb);
    ~pipe_watcher();

    bool asy_wait();
    void notify();
  protected:
    static void thread_libevent_process(int fd, short which, void* me);

  private:
    virtual bool on_init();
    virtual void on_close();
  private:
    int notify_receive_fd_;
    int notify_send_fd_;
  };

}
