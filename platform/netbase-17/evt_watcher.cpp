#include "evt_watcher.h"
namespace netb {
  evt_watcher::~evt_watcher()
  {

  }

  bool evt_watcher::init()
  {
    if (!on_init()) {
      goto FAILED;
    }

    return ::event_base_set(evbase_, notify_event_) == 0;

  FAILED:
    close();
    return false;
  }

  evt_watcher::evt_watcher(struct event_base* base, const handler & cb)
    : evbase_(base)
    , attached_(false)
    , cb_libevent_process_(cb)
    //, event_(new event)
  {
    notify_event_ = (struct event*)malloc(sizeof(struct event));
    memset(notify_event_, 0, sizeof(struct event));

    
  }

  void evt_watcher::close()
  {
    on_close();
  }



  //////////////////////////////////////////////////////////////////////////

  pipe_watcher::pipe_watcher(evt_loop* loop, const handler& cb)
    : evt_watcher(/*loop->*/ nullptr, cb)
  {
    
  }

  pipe_watcher::~pipe_watcher()
  {

  }

  bool pipe_watcher::asy_wait()
  {
    return false;
  }

  void pipe_watcher::notify() {
    char buf[1] = {};

    if (::send(notify_send_fd_, buf, sizeof(buf), 0) < 0) {
      return;
    }
  }

  void pipe_watcher::thread_libevent_process(int fd, short which, void* arg) {
    pipe_watcher* me = (pipe_watcher*)arg;
    char buf[1];
    if (::recv(fd, buf, sizeof buf, 0) != 1) {
      return;
    }

    switch (buf[0]) {
    case 's':
      event_base_loopexit(me->evbase_, NULL);
      break;
    default:
      me->cb_libevent_process_();
    }
  }

  bool pipe_watcher::on_init() {
    int fds[2];
    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
      int err = errno;
      //LOG_ERROR << "create socketpair ERROR errno=" << err << " " << strerror(err);
      goto FAILED;
    }

    notify_receive_fd_ = fds[0];
    notify_send_fd_ = fds[1];

    if (evutil_make_socket_nonblocking(notify_receive_fd_) < 0 ||
      evutil_make_socket_nonblocking(notify_send_fd_) < 0) {
      goto FAILED;
    }

    return event_assign(notify_event_, evbase_, notify_receive_fd_, EV_READ | EV_PERSIST,
      &pipe_watcher::thread_libevent_process, this) == 0;

//     ::event_set(notify_event_, notify_send_fd_, EV_READ | EV_PERSIST,
//       &pipe_watcher::thread_libevent_process, this);
//    return true;
  
  FAILED:
    close();
    return false;
  }

  void pipe_watcher::on_close() {
    if (notify_receive_fd_ > 0) {
      EVUTIL_CLOSESOCKET(notify_receive_fd_);
      notify_receive_fd_ = 0;
    }
    if (notify_send_fd_ > 0) {
      EVUTIL_CLOSESOCKET(notify_send_fd_);
      notify_send_fd_ = 0;
    }
  }

}