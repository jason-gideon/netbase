#pragma once

#include <vector>
#include <mutex>

#include "netb.h"

class conn_factory {
public:
  /*
  * ����������
  */
  virtual ~conn_factory() = 0;

  /*
* ��ȡһ�����е�����ڵ�
*/
  conn *conn_new(int sfd);

  void conn_free(conn *c);


  /*
* ������ʵ�֣� ������һ����������ڵ�
*/
  virtual conn *create_task_node() = 0;

  /*
  * ��ȡ�ڵ�����
  */
  int total();

public:
  int maxfd() {
    return max_fds;
  }

protected:
  /** ���ι��캯�� */
  conn_factory(int maxconns);

  void conn_init(void);

protected:

  /** �������� */
  std::vector <conn*> conns;

  /** �������� */
  std::mutex mtx;

  int max_fds;
};

