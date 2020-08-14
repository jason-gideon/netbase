/************************************************************************
* File Name: BaseSocket.h
* Version: 1.0.0, Data: 2015 7 21
* Description: 网络套接字封装
* 
*socket说明
*第一、socket  steps:
*SVR(4-steps):
*1.create;
*2.bind;
*3.listen;
*4.accept;
**********
*5.send;
*6.recv;
*
*Client()
*1.create;
*2.connect;
*
*第二、阻塞与非阻塞
*1.accept;
*2.connect;
*3.send;
*4.recv;
*
*注意: 本封装采用的是select模型，在大并发的时候，
*不适用。
*大并发应采用完成端口或epoll
*
* Other:
* Function List:
* History:
* <author> <time>     <version> <desc>
* jason      2015-7-21  1.0.0     创建
* jason		  2016-12-27 1.0.1	 添加socketpair	
************************************************************************/

#ifndef __BASE_SOCKET_H__
#define __BASE_SOCKET_H__


#ifdef __cplusplus
extern "C"
{
#endif


#ifndef INVALID_SOCKET 
#define INVALID_SOCKET (-1)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

	/*******************************************************************************
	*Function: SocketCreate
	*Description: 创建socket (Client & SVR)
	*Input:
	* af       [I] af parameter, AF_INET, ...
	* type     [I] SOCK_STREAM, SOCK_DGRAM, ...
	* protocol [I] IPPROTO_TCP, ...
	*Output:
	*Return: (套接字socket fd) - 成功，(INALID_SOCEKT) - 失败
	*Other:
	*******************************************************************************/
	int socket_create(int nAf, int nType, int nProtocol);


	/*******************************************************************************
	*Function: SocketDestroy
	*Description: 销毁socket (Client & SVR)
	*Input:
	* nFd       [I] socket handle
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	void socket_destroy(int nFd);

	/*******************************************************************************
	*Function: SocketBind
	*Description: 绑定socket(SVR)
	*Input:
	* nFd       [I] socket handle;
	* pszIp     [I] local ip;
	* nPort     [I] local port;
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_bind(int nFd, char* pszIp, int nPort);

	/*******************************************************************************
	*Function: SocketListen
	*Description: 监听socket(SVR)
	*Input:
	* nFd       [I] socket handle
	* nMax     [I] 等待连接队列的最大长度,超过该数目的连接请求
	*					被拒绝
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_listen(int nFd, int nMax);

	/*******************************************************************************
	*Function: SocketAccept
	*Description: 服务器接受客户端的socket(SVR)
	*Input:
	* nFd       [I] socket 句柄
	* pszIp     [O] 返回的client IP
	* pPort    [O] 返回的client Port
	* nTimeOut [I] > 0, 为accept阻塞时间; = 0 为一直阻塞;
	*Output:
	*Return: (套接字socket fd) - 成功，(INALID_SOCEKT) - 失败，(0) - 超时
	*Other:
	*******************************************************************************/
	int socket_accept(int nFd, char* pszIp, int *pPort, int nTimeOut);


	/*******************************************************************************
	*Function: SocketConnect
	*Description: 连接远端
	*Input:
	* fd      [I] socket fd
	* ip      [I] 远端ip
	* port    [I] 远端port
	* timeout [I] 连接超时,timeout=-1表示无限等待
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_connect(int nFd, char* pszIp, int nPort, int nTimeOut);

	/*******************************************************************************
	*Function: SocketSetNonBlock
	*Description: 设置非阻塞
	*Input:
	* fd      [I] socket fd
	* flags   [I] 标识位值，如O_NONBLOCK为非阻塞
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_setnonblock(int nFd);

	/*******************************************************************************
	*Function: SocketSetBlock
	*Description: 设置为阻塞
	*Input:
	* fd      [I] socket fd
	* flags   [I] 标识位值，如O_NONBLOCK为非阻塞
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_setblock(int nFd);

	/*******************************************************************************
	*Function: SocketIOControl
	*Description: 输入输出控制
	*Input:
	* nFd   [I] socket fd
	* nType [I] 操作类型
	* nVal  [I] 值, ...
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_ioctl(int nFd, int nType, unsigned int *nVal);

	/*******************************************************************************
	*Function: SocketSend
	*Description: 发送数据
	*Input:
	* fd       [I] socket fd
	* buf      [I] 缓冲区
	* size     [I] 发送数据大小
	* timeout  [I] 超时，毫秒
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_send(int nFd, void *pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketRecv
	*Description: 接收数据
	*Input:
	* fd       [I] socket fd
	* buf      [I] 缓冲区
	* size     [I] 缓冲区大小
	* timeout  [I] 超时，毫秒
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_recv(int nFd, void *pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketSendTo
	*Description: 发送数据
	*Input:
	* fd      [I] socket fd
	* ip      [I] 远端ip
	* port    [I] 远端port
	* buf     [I] 缓冲区
	* size    [I] 发送数据大小
	* timeout [I] 超时，毫秒
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_sendto(int nFd, char* pszIp, int nPort, void* pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketRecvFrom
	*Description: 接收数据
	*Input:
	* fd      [I] socket fd
	* ip      [O] 远端ip
	* port    [O] 远端port
	* buf     [IO] 缓冲区
	* size    [I] 缓冲区大小
	* timeout [I] 超时，毫秒
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_recvfrom(int nFd, char* pszIp, int *pPort, void* pBuf, int nSizen, int nTimeOut);


	/*******************************************************************************
	*Function: socket_opt
	*Description: 设置参数，调用setsocketopt
	*Input:
	* fd      [I] socket fd
	* level   [I] level
	* optname [I] option name
	* optval  [I] option value
	* optlen  [I] option length
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_opt(int fd, int level, int optname, const char* optval, int optlen);

	/*******************************************************************************
	*Function: socket_pair
	*Description: 创建两个随后连接起来的sock
	*	类似于管道，但是是全双工管道。
	*Input:
	* family      [I] 地址族
	* type   [I] sock 类型,SOCK_STREAM, SOCK_DGRAM, ...
	* protocol [I] IPPROTO_TCP, ..., 默认填写0
	* sfd[2]  [O] 生成的sockfd
	*Output:
	*Return: (0) - 成功，(-1) - 失败
	*Other:
	*******************************************************************************/
	int socket_pair(int family, int type, int protocol, int sfd[2]);


  /*******************************************************************************
*Function: SocketSend
*Description: 发送数据
*Input:
* fd       [I] socket fd
* buf      [I] 缓冲区
* size     [I] 发送数据大小
* timeout  [I] 超时，毫秒
*Output:
*Return: (0) - 成功，(-1) - 失败
*Other:
*******************************************************************************/
  int socket_read(int nFd, char *pBuf, int nSize);

  /*******************************************************************************
  *Function: SocketRecv
  *Description: 接收数据
  *Input:
  * fd       [I] socket fd
  * buf      [I] 缓冲区
  * size     [I] 缓冲区大小
  * timeout  [I] 超时，毫秒
  *Output:
  *Return: (0) - 成功，(-1) - 失败
  *Other:
  *******************************************************************************/
  int socket_write(int nFd, const char *pBuf, int nSize);


  void maximize_sndbuf(const int sfd);

#ifdef __cplusplus
}
#endif

#endif
