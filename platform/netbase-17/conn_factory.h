#pragma once

#include <vector>
#include <mutex>

#include "netb.h"

class conn_factory {
public:
  /*
  * 虚析构函数
  */
  virtual ~conn_factory() = 0;

  /*
* 获取一个空闲的任务节点
*/
  conn *conn_new(int sfd);

  void conn_free(conn *c);


  /*
* 由子类实现， 新生成一个任务子类节点
*/
  virtual conn *create_task_node() = 0;

  /*
  * 获取节点总数
  */
  int total();

public:
  int maxfd() {
    return max_fds;
  }

protected:
  /** 屏蔽构造函数 */
  conn_factory(int maxconns);

  void conn_init(void);

protected:

  /** 任务链表 */
  std::vector <conn*> conns;

  /** 链表互斥锁 */
  std::mutex mtx;

  int max_fds;
};

