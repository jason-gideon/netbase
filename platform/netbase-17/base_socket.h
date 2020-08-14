/************************************************************************
* File Name: BaseSocket.h
* Version: 1.0.0, Data: 2015 7 21
* Description: �����׽��ַ�װ
* 
*socket˵��
*��һ��socket  steps:
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
*�ڶ��������������
*1.accept;
*2.connect;
*3.send;
*4.recv;
*
*ע��: ����װ���õ���selectģ�ͣ��ڴ󲢷���ʱ��
*�����á�
*�󲢷�Ӧ������ɶ˿ڻ�epoll
*
* Other:
* Function List:
* History:
* <author> <time>     <version> <desc>
* jason      2015-7-21  1.0.0     ����
* jason		  2016-12-27 1.0.1	 ���socketpair	
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
	*Description: ����socket (Client & SVR)
	*Input:
	* af       [I] af parameter, AF_INET, ...
	* type     [I] SOCK_STREAM, SOCK_DGRAM, ...
	* protocol [I] IPPROTO_TCP, ...
	*Output:
	*Return: (�׽���socket fd) - �ɹ���(INALID_SOCEKT) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_create(int nAf, int nType, int nProtocol);


	/*******************************************************************************
	*Function: SocketDestroy
	*Description: ����socket (Client & SVR)
	*Input:
	* nFd       [I] socket handle
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	void socket_destroy(int nFd);

	/*******************************************************************************
	*Function: SocketBind
	*Description: ��socket(SVR)
	*Input:
	* nFd       [I] socket handle;
	* pszIp     [I] local ip;
	* nPort     [I] local port;
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_bind(int nFd, char* pszIp, int nPort);

	/*******************************************************************************
	*Function: SocketListen
	*Description: ����socket(SVR)
	*Input:
	* nFd       [I] socket handle
	* nMax     [I] �ȴ����Ӷ��е���󳤶�,��������Ŀ����������
	*					���ܾ�
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_listen(int nFd, int nMax);

	/*******************************************************************************
	*Function: SocketAccept
	*Description: ���������ܿͻ��˵�socket(SVR)
	*Input:
	* nFd       [I] socket ���
	* pszIp     [O] ���ص�client IP
	* pPort    [O] ���ص�client Port
	* nTimeOut [I] > 0, Ϊaccept����ʱ��; = 0 Ϊһֱ����;
	*Output:
	*Return: (�׽���socket fd) - �ɹ���(INALID_SOCEKT) - ʧ�ܣ�(0) - ��ʱ
	*Other:
	*******************************************************************************/
	int socket_accept(int nFd, char* pszIp, int *pPort, int nTimeOut);


	/*******************************************************************************
	*Function: SocketConnect
	*Description: ����Զ��
	*Input:
	* fd      [I] socket fd
	* ip      [I] Զ��ip
	* port    [I] Զ��port
	* timeout [I] ���ӳ�ʱ,timeout=-1��ʾ���޵ȴ�
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_connect(int nFd, char* pszIp, int nPort, int nTimeOut);

	/*******************************************************************************
	*Function: SocketSetNonBlock
	*Description: ���÷�����
	*Input:
	* fd      [I] socket fd
	* flags   [I] ��ʶλֵ����O_NONBLOCKΪ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_setnonblock(int nFd);

	/*******************************************************************************
	*Function: SocketSetBlock
	*Description: ����Ϊ����
	*Input:
	* fd      [I] socket fd
	* flags   [I] ��ʶλֵ����O_NONBLOCKΪ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_setblock(int nFd);

	/*******************************************************************************
	*Function: SocketIOControl
	*Description: �����������
	*Input:
	* nFd   [I] socket fd
	* nType [I] ��������
	* nVal  [I] ֵ, ...
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_ioctl(int nFd, int nType, unsigned int *nVal);

	/*******************************************************************************
	*Function: SocketSend
	*Description: ��������
	*Input:
	* fd       [I] socket fd
	* buf      [I] ������
	* size     [I] �������ݴ�С
	* timeout  [I] ��ʱ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_send(int nFd, void *pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketRecv
	*Description: ��������
	*Input:
	* fd       [I] socket fd
	* buf      [I] ������
	* size     [I] ��������С
	* timeout  [I] ��ʱ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_recv(int nFd, void *pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketSendTo
	*Description: ��������
	*Input:
	* fd      [I] socket fd
	* ip      [I] Զ��ip
	* port    [I] Զ��port
	* buf     [I] ������
	* size    [I] �������ݴ�С
	* timeout [I] ��ʱ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_sendto(int nFd, char* pszIp, int nPort, void* pBuf, int nSize, int nTimeOut);

	/*******************************************************************************
	*Function: SocketRecvFrom
	*Description: ��������
	*Input:
	* fd      [I] socket fd
	* ip      [O] Զ��ip
	* port    [O] Զ��port
	* buf     [IO] ������
	* size    [I] ��������С
	* timeout [I] ��ʱ������
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_recvfrom(int nFd, char* pszIp, int *pPort, void* pBuf, int nSizen, int nTimeOut);


	/*******************************************************************************
	*Function: socket_opt
	*Description: ���ò���������setsocketopt
	*Input:
	* fd      [I] socket fd
	* level   [I] level
	* optname [I] option name
	* optval  [I] option value
	* optlen  [I] option length
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_opt(int fd, int level, int optname, const char* optval, int optlen);

	/*******************************************************************************
	*Function: socket_pair
	*Description: ���������������������sock
	*	�����ڹܵ���������ȫ˫���ܵ���
	*Input:
	* family      [I] ��ַ��
	* type   [I] sock ����,SOCK_STREAM, SOCK_DGRAM, ...
	* protocol [I] IPPROTO_TCP, ..., Ĭ����д0
	* sfd[2]  [O] ���ɵ�sockfd
	*Output:
	*Return: (0) - �ɹ���(-1) - ʧ��
	*Other:
	*******************************************************************************/
	int socket_pair(int family, int type, int protocol, int sfd[2]);


  /*******************************************************************************
*Function: SocketSend
*Description: ��������
*Input:
* fd       [I] socket fd
* buf      [I] ������
* size     [I] �������ݴ�С
* timeout  [I] ��ʱ������
*Output:
*Return: (0) - �ɹ���(-1) - ʧ��
*Other:
*******************************************************************************/
  int socket_read(int nFd, char *pBuf, int nSize);

  /*******************************************************************************
  *Function: SocketRecv
  *Description: ��������
  *Input:
  * fd       [I] socket fd
  * buf      [I] ������
  * size     [I] ��������С
  * timeout  [I] ��ʱ������
  *Output:
  *Return: (0) - �ɹ���(-1) - ʧ��
  *Other:
  *******************************************************************************/
  int socket_write(int nFd, const char *pBuf, int nSize);


  void maximize_sndbuf(const int sfd);

#ifdef __cplusplus
}
#endif

#endif
