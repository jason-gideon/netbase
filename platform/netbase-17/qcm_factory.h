#pragma once

#include "conn_factory.h"

class qcm_conn : public conn
{
public:
  qcm_conn() {

  }
  ~qcm_conn() {

  }

private:

};


class qcm_factory : public conn_factory {
public:
  qcm_factory();

  ~qcm_factory();

  conn *create_task_node();
};

