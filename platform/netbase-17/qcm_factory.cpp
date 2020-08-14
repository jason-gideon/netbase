#include "qcm_factory.h"

qcm_factory::qcm_factory()
  : conn_factory(10000)
{

}

qcm_factory::~qcm_factory()
{

}

conn * qcm_factory::create_task_node()
{
  conn *ptask = NULL;

  try
  {
    ptask = new (std::nothrow) qcm_conn();
  }
  catch (...)
  {
    //LOG4(log4::ERROR_LOG4_LEVEL, "Failed to new MuClientTcp");
  }

  return ptask;
}
