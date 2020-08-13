
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <sstream>
#include <iostream>

#ifdef WIN32
#include <Winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <stdint.h>
#include <unistd.h>	/*���ų���*/
#include <fcntl.h>	/*�ļ�����*/
#include <netdb.h>
#include <dirent.h>
#include <pthread.h>
#include <inttypes.h>
#include <semaphore.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
//#include <bits/types.h>
#include <sys/ipc.h> /*IPC*/
//#include <sys/sem.h>
#include <sys/stat.h> /*�ļ�״̬*/
#include <sys/sysinfo.h> /**/
#include <sys/mman.h>
#include <sys/vfs.h>
#include <linux/unistd.h>
#endif

#include "base_socket.h"


#ifdef WIN32
/*local scope funcs*/
static int __stream_socketpair(struct addrinfo* ai,int sock[2])
{
	/*client socket*/
	int c_socket = INVALID_SOCKET;
	/*server socket*/
	int s_socket = INVALID_SOCKET;

	int opt = 1;

#ifdef WIN32
	int addrlen_ai;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	socklen_t addrlen_ai;
#endif


	/*listener socket*/
	int l_socket = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if (INVALID_SOCKET==l_socket)
		goto fail;

	setsockopt(l_socket,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt, sizeof(opt));

	if(-1==bind(l_socket,ai->ai_addr,ai->ai_addrlen))
		goto fail;

#ifdef WIN32
	addrlen_ai = ai->ai_addrlen;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	addrlen_ai = ai->ai_addrlen;
#endif

	if (-1==getsockname(l_socket,ai->ai_addr, &addrlen_ai))
		goto fail;

	if(-1==listen(l_socket,SOMAXCONN))
		goto fail;

	c_socket = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if (INVALID_SOCKET==c_socket)
		goto fail;

	if (-1==connect(c_socket,ai->ai_addr,ai->ai_addrlen))
		goto fail;

	s_socket = accept(l_socket,0,0);
	if (INVALID_SOCKET==s_socket)
		goto fail;

	socket_destroy(l_socket);

	sock[0] = c_socket;
	sock[1] = s_socket;

	return 0;

fail:
	if(INVALID_SOCKET!=l_socket)
		socket_destroy(l_socket);
	if (INVALID_SOCKET!=c_socket)
		socket_destroy(c_socket);

	return -1;
}

static int __dgram_socketpair(struct addrinfo* ai,int sock[2])
{
	int c_socket = INVALID_SOCKET;
	int s_socket=INVALID_SOCKET;
	struct addrinfo addr,*res = NULL;
	const char* address = NULL;
	int opt = 1;
	
#ifdef WIN32
	int addrlen_ai;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	socklen_t addrlen_ai;
#endif

	
#ifdef WIN32
	int addrlen_res;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	socklen_t addrlen_res;
#endif

	s_socket = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if (INVALID_SOCKET==s_socket)
		goto fail;

	setsockopt(s_socket,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt, sizeof(opt));

	if(-1==bind(s_socket,ai->ai_addr,ai->ai_addrlen))
		goto fail;

	
#ifdef WIN32
	addrlen_ai = ai->ai_addrlen;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	addrlen_ai = ai->ai_addrlen;
#endif

	if (-1==getsockname(s_socket,ai->ai_addr, &addrlen_ai))
		goto fail;

	c_socket = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if (INVALID_SOCKET==c_socket)
		goto fail;

	memset(&addr,0,sizeof(addr));
	addr.ai_family = ai->ai_family;
	addr.ai_socktype = ai->ai_socktype;
	addr.ai_protocol = ai->ai_protocol;

	if (AF_INET6==addr.ai_family)
		address = "0:0:0:0:0:0:0:1";
	else
		address = "127.0.0.1";

	if (getaddrinfo(address,"0",&addr,&res))
		goto fail;

	setsockopt(c_socket,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt, sizeof(opt));
	if(-1==bind(c_socket,res->ai_addr,res->ai_addrlen))
		goto fail;

	
#ifdef WIN32
	addrlen_res = res->ai_addrlen;
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	addrlen_res = res->ai_addrlen;
#endif

	if (-1==getsockname(c_socket,res->ai_addr,&addrlen_res))
		goto fail;

	if (-1==connect(s_socket,res->ai_addr,res->ai_addrlen))
		goto fail;

	if (-1==connect(c_socket,ai->ai_addr,ai->ai_addrlen))
		goto fail;

	freeaddrinfo(res);

	sock[0] = c_socket;
	sock[1] = s_socket;

	return 0;

fail:
	if (INVALID_SOCKET!=c_socket)
		socket_destroy(c_socket);

	if (INVALID_SOCKET!=s_socket)
		socket_destroy(s_socket);

	if (res)
		freeaddrinfo(res);

	return -1;		
}


static int win32_socketpair(int family,int type,int protocol,int sock[2])
{
	const char* address = NULL;
	struct addrinfo addr,*ai;
	int ret = -1;

	memset(&addr,0,sizeof(addr));
	addr.ai_family = family;
	addr.ai_socktype = type;
	addr.ai_protocol = protocol;

	if (AF_INET6==family)
		address = "0:0:0:0:0:0:0:1";
	else
		address = "127.0.0.1";


	if (0==getaddrinfo(address,"0",&addr,&ai))	{

		if (SOCK_STREAM==type)
			ret = __stream_socketpair(ai,sock);
		else if(SOCK_DGRAM==type)
			ret = __dgram_socketpair(ai,sock);

		freeaddrinfo(ai);
	}

	return ret;	
}

#endif // WIN32

/*
 *linger
 *
 *
 */
int socket_create( int nAf, int nType, int nProtocol )
{
	int nFd = (int)socket(nAf, nType, nProtocol);

#ifdef WIN32
#else

	if (nFd != INVALID_SOCKET )
	{
		/*
		 *����socketΪǿ�ƹر�
		 *close(fd)ʱ��tcpز�ۣ����������
		 *�������˴�Ϊ�˱���TIME_WAIT
		 */
		struct linger lgr;
		lgr.l_onoff = 1;
		lgr.l_linger = 0;
		setsockopt(nFd, SOL_SOCKET, SO_LINGER, (const char*)&lgr, sizeof(lgr));

		/*
		 *����socket���ջ�������С
		 *UNIX�»���������������й�
		 *window������޹أ�Ĭ��ֵ���ɡ�(δ���Բ���)
		 */
		int nRecvBuf  = 32*1024; /*32K*/
		setsockopt(nFd, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int));

		/*
		 *����socket���ͻ�������С
		 *UNIX�»���������������й�
		 *window������޹أ�Ĭ��ֵ���ɡ�(δ���Բ���)
		 */
		int nSendBuf  = 32*1024; /*32K*/
		setsockopt(nFd, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));

		/*
		 *����socket���ͽ��ܳ�ʱʱ��
		 */
		int nNetTimeOut = 1000;
		setsockopt(nFd, SOL_SOCKET, SO_SNDTIMEO, (char*)&nNetTimeOut, sizeof(int));
		setsockopt(nFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeOut, sizeof(int));
		
	}

#endif // WIN32

	return nFd;
}

int socket_bind( int nFd, char* pszIp, int nPort )
{
	if (nFd == INVALID_SOCKET )
	{
		return -1 ;
	}

	/*����յ�ַ�壬���򣬲�ͬ������Э�飬ֵ��ͬ*/
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	/*IPV4*/
	addr.sin_family = AF_INET; 

	/*
	 *��ǰsocket���󶨵Ķ˿�
	 *�˿���ҪתΪ�����ֽ���
	 */
	addr.sin_port = htons(nPort); 

	/*
	 *��ǰsocket���󶨵�IP
	 *
	 *ע��:inet_addr()����32λIPV4�������ֽ���
	 *��ַ��
	 *�������⣬��Ϊ����ֵ1111 1111 1111 1111Ϊ
	 *255.255.255.255����ʧ��ֵ��ͻ����ˣ��ܶ�
	 *�����ܱ�ʾ��
	 */
	addr.sin_addr.s_addr = (pszIp == NULL ? htonl(INADDR_ANY) : inet_addr(pszIp)); 

	/*
	 *��socket������ָ����ַ��
	 *����ʹ�õ���·Э�鲻ͬ����ͬ��
	 *��ˣ���Ҫ����������ָ������
	 */
	return bind(nFd, (struct sockaddr *)&addr, sizeof(sockaddr_in));

}

int socket_accept( int nFd, char* pszIp, int *pPort, int nTimeOut )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

	int nRet = 0;
	struct sockaddr_in From;
	
	/*
	 *����acceptǰ�����һ����
	 *���ȱ�����sockaddr_in, ����,
	 *accept�����
	 **/
#ifdef WIN32
	int nAddrLen = sizeof(From);
#else
	/*UNIX/Linux����Ҫָ��socklen,64λ����int��socklen_t
	 *���Ȳ�һ��*/
	socklen_t nAddrLen = sizeof(From);
#endif

	/*����:
	 *1.accept�Ƿ������������������?
	 *
	 *��:socket accept���������⣬��δ�����
	 *connect������û��δ�������������������
	 *socket�£�accept�����������ߣ�ֱ����connection������
	 *
	 *
	 *2.���У��˴�socket accept��������?
	 *��: ���ڴ�������socket���⣬��ˣ�����ȡ������
	 *������Ҫʹ��select����socket��������Ϊ������socket
	 *
	 */

	if (nTimeOut > 0)
	{		
		/*
		 *����ʱֵ����0������÷���������һ��ʱ����û��
		 *connection�ȴ����Ӷ����У�û�������������˳�
		*/
		fd_set ReadSet;
		struct timeval TimeVal;

		/*��ȡ����ʱ��*/
		TimeVal.tv_sec = nTimeOut / 1000; 
		TimeVal.tv_usec = (nTimeOut % 1000) * 1000;

		FD_ZERO(&ReadSet);
		FD_SET(nFd, &ReadSet);
		/*selectָ���������ĸ������������ֵ
		 *��������0��ʼ*/
		nRet = select(nFd + 1, &ReadSet, 0, 0, &TimeVal);

		/*select��ʱ*/
		if (nRet == 0)
		{
			return 0;
		}
		else if (nRet < 0) /*socket�쳣*/
		{
			return -1;
		}
	}

	/*�ɹ���������ʵ������socket*/
	int nClientFd = (int)accept(nFd, (struct sockaddr*)&From, &nAddrLen);

	if (nClientFd != INVALID_SOCKET)
	{
		/*�ɹ���¼�ͻ��˵�IP��Port*/
		sprintf(pszIp, "%s", inet_ntoa(From.sin_addr));
		*pPort = ntohs(From.sin_port);
	}
	else
	{
		return 0;
	}

	return nClientFd;
}

/*
 *˵��: socket�еȴ����е���󳤶�
 *
 *@backlog: 
 *
 *listen�У�backlog��Ϊ�����õȴ����Ӷ��е�
 *��󳤶ȣ���������һ���˿���ͬʱ���Խ�
 *�����ӵ���Ŀ��
 *
 *����:backlog == 2ʱ�� ������������ͬʱ���
 *ǰ������������ͻᱻ�ŵ��ȴ������У�Ȼ��
 *��App����Ϊ��Щ������񣬵���������ͱ�
 *�ܾ��ˡ�
 *
 */
int socket_listen( int nFd, int nMax )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

	/*����*/
	return listen(nFd, nMax);
}


int socket_connect( int nFd, char* pszIp, int nPort, int nTimeOut )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

	int nRet = 0;
	struct sockaddr_in nAddr;
	//int nAddrLen = sizeof(struct sockaddr);
	
	memset(&nAddr, 0, sizeof(nAddr));
	
	/*���Ҫ���ӵ�Ŀ�Ķ˵�ַ(SVR)*/
	nAddr.sin_family = AF_INET;
	nAddr.sin_port = htons(nPort);
	nAddr.sin_addr.s_addr = inet_addr(pszIp);

	/*�����С��0�������������ʽ*/
	if (nTimeOut < 0)
	{
		/*
		 *1.�����������ӵ�socket, ������ʽ����ȵ��Է��ķ��ء�
		 *
		 *2.���������ӵ�socket��������ʽ�е�connect,����Ϊ�����
		 *send��recv���ý���һ��Ĭ�ϵ�Ŀ���ַ��
		 */
		return connect(nFd, (const struct sockaddr*)&nAddr, sizeof(nAddr));
	}

	/*
	 *��������ʽ
	 *
	 *������socket connect��ʽ������Ϊ������connect
	 */
	if (socket_setnonblock(nFd) == -1)
	{
		return -1;
	}

	nRet = connect(nFd, (struct sockaddr*)&nAddr, sizeof(nAddr));

	/*
	 *������ģʽ�£����������ӳɹ�����socket
	 *����Ϊ������ʽ��������
	 */
	if (nRet == 0)
	{
		socket_setblock(nFd);
		
		return nRet;
	}

#ifdef WIN32

	/*
	 *��������socket connect���������쳣
	 *������쳣������Ϊ�����˳�
	 *
	 *MSDN
	 *This error is returned from operations on 
	 *nonblocking sockets that cannot be completed
	 *immediately, for example recv when no data is
	 *queued to be read from the socket. It is a nonfatal
	 *error, and the operation should be retried later. 	
	 *
	 *It is normal for WSAEWOULDBLOCK to be 
	 *reported as the result from calling connect on
	 *a nonblocking SOCK_STREAM socket, since
	 *some time must elapse for the connection to be
	 *established.
	 */
	if (WSAGetLastError() != WSAEWOULDBLOCK)
	{
		socket_setblock(nFd);

		return nRet;
	}


#else
#endif // _DEBUG

	/*MSDN: ���ڷ�����socket������������������ɣ�����
	 *WSAEWOULDBLOCK������ͨ��select��ѯsocket�Ƿ��д
	 *ͨ��select��ѯ*/
	fd_set WriteSet;
	struct timeval TimeVal;

	/*��ȡ����ʱ��*/
	TimeVal.tv_sec = nTimeOut / 1000; 
	TimeVal.tv_usec = (nTimeOut % 1000) * 1000;

	FD_ZERO(&WriteSet);
	FD_SET(nFd, &WriteSet);/*��������Fd���뼯��*/

	/*���TcpЭ��ջ�յ���SVR���͹�����Ӧ��socket��Ӧ������*/
	if (select(nFd + 1, 0, &WriteSet, 0, &TimeVal) > 0)
	{
		int nError = -1;
		int nLen = sizeof(int);

		/*����fd���е�һ������λ�Ƿ��Ƿ��Դ��ڴ�״̬
		 *��ָFD_SETĳ��fd*/
		if (FD_ISSET(nFd, &WriteSet))
		{
			/*ͨ���ӿڲ�ѯsocket���쳣*/
			if (getsockopt(nFd, SOL_SOCKET, SO_ERROR, (char*)&nError, (socklen_t*)&nLen) < 0)
			{
				/*�ӿڵ����쳣*/
				socket_setblock(nFd);
				return -1;
			}

			/*û�в�ѯ��socket�쳣*/
			if (nError == 0)
			{
				nRet = 0;
			}
			else
			{
				nRet = -1;
			}
		}
		else
		{
			nRet = -1;
		}

	}
	else
	{
		nRet = -1;
	}

	socket_setblock(nFd);


	
	return nRet;

}

int socket_setnonblock( int nFd )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}
	unsigned int nNonBlocking = -1;

	return socket_ioctl(nFd, FIONBIO, &nNonBlocking);
}

int socket_ioctl( int nFd, int nType, unsigned int *nVal )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

#ifdef WIN32
	return ioctlsocket(nFd, (long)nType, (u_long*)nVal);
#else
	return ioctl(nFd, nType, nVal);
#endif
}

int socket_setblock( int nFd )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

	unsigned int unBlocking = 0;

	return socket_ioctl(nFd, FIONBIO, &unBlocking);
}

void socket_destroy( int nFd )
{
	if (nFd != INVALID_SOCKET)
	{
#ifdef WIN32
		closesocket(nFd);
#else
		close(nFd);
#endif
	}
}

int socket_send( int nFd, void *pBuf, int nSize, int nTimeOut )
{
	if ((nFd == INVALID_SOCKET) || (pBuf == NULL))
	{
		return -1;
	}

	int nSendTimes = 0;
	int nLeft = nSize;
	int nWritten = 0;

	char *p = (char*)pBuf;


	while (nLeft > 0)
	{
		struct timeval TimeVal;
		fd_set WriteSet;
		int nRet = 0;

		/*���set������bit*/
		FD_ZERO(&WriteSet);
		/*��set�п���fd�ı�־*/
		FD_SET(nFd, &WriteSet);

		TimeVal.tv_sec = nTimeOut/1000;
		TimeVal.tv_usec = (nTimeOut%1000)*1000;
		/*selectģ�����֧��1024��������������1024��poll
		 *�鿴��ǰfd�Ƿ��д*/
		nRet = select(nFd+1, NULL, &WriteSet, NULL, &TimeVal); // NULL

		/*����select�쳣*/
		if (nRet < 0)
		{
			/*
			 *��׼C�£������ź��жϣ�ûд�ɹ��κ�����
			 *
			 *���������һ����ϵͳ����(slow system call)��
			 *����ʱ��������ĳ���ź�����Ӧ�źŴ���
			 *������ʱ�����ϵͳ���ñ��жϣ����÷��ش�
			 *������errnoΪEINTR
			 */
			if (errno == EINTR)
			{
				/*����������γ�ʱ������0*/
				nSendTimes ++;
				if (nSendTimes > 2)
				{
					return 0;
				}

				continue;
			}

			return -1;				
		}
		else if (0 == nRet) /*select��ʱ*/
		{
			/*����������γ�ʱ������0*/
			nSendTimes ++;
			if (nSendTimes > 2)
			{
				return 0;
			}

			continue;
		}
		else
		{
			/*��ʼ����*/
			if (FD_ISSET(nFd, &WriteSet))
			{

				if ((nWritten = send(nFd, p, nLeft, 0)) <= 0)
				{
					/*
					 *�����쳣
					 *
					 *��linux���з�������socket��������ʱ
					 *��������Resource temporarily unavailable��
					 *errno����Ϊ11(EAGAIN)����������ڷ�
					 *����ģʽ�µ����������������ڸò�
					 *��û����ɾͷ���������������
					 *�󲻻��ƻ�socket��ͬ��
					 */
					if ((errno == EINTR) || (errno == EAGAIN))			
					{
						nWritten = 0;

						nSendTimes ++;
						if (nSendTimes > 2) // ����������η��Ͳ���ȥ������0
						{
							return 0;
						}

						continue;	  			
					}	

					return -1;
				}

				nLeft = nLeft - nWritten;
				p = p + nWritten;

			}
		}

	}
	return nSize;
}

/*
*Function: recv
*Description: ��������
*Return:
*	0 : the connection has been gracefully closed.
*	>0: the number of bytes received.
*	<0: socket error is returned.
*
*/
int socket_recv( int nFd, void *pBuf, int nSize, int nTimeOut )
{
	if ((nFd == INVALID_SOCKET) || (pBuf == NULL))
	{
		return -1;
	}

	/*����ģʽ��ֱ�ӽ�������*/
	if (nTimeOut < 0)
	{
		return recv(nFd, (char*)pBuf, nSize, 0);
	}


	/*������ģʽ����select��ѯ���ٽ���*/
	int nRet = 0;
	fd_set ReadSet;
	struct timeval tv;

	tv.tv_sec = nTimeOut/1000;
	tv.tv_usec = (nTimeOut%1000)*1000;

	FD_ZERO(&ReadSet);
	FD_SET(nFd, &ReadSet);

	nRet = select(nFd+1, &ReadSet, 0, 0, &tv);

	if (nRet == 0)
	{
		return 0;
	}
	else if (nRet < 0)
	{
		return -1;
	}

	return recv(nFd, (char*)pBuf, nSize, 0);
}

int socket_sendto( int nFd, char* pszIp, int nPort, void* pBuf, int nSize, int nTimeOut )
{
	if ((nFd == INVALID_SOCKET) || (pBuf == NULL))
	{
		return -1;
	}

	struct sockaddr_in addr;
	int nLen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(pszIp);
	addr.sin_port        = htons(nPort);

	/*������*/
	if (nTimeOut < 0)
	{
		return sendto(nFd, (char*)pBuf, nSize, 0, (struct sockaddr *)&addr, nLen);
	}

	/*��������*/
	int nRet = 0;
	fd_set WriteSet;
	struct timeval tv;

	tv.tv_sec = nTimeOut/1000;
	tv.tv_usec = (nTimeOut%1000)*1000;

	FD_ZERO(&WriteSet);
	FD_SET(nFd, &WriteSet);

	nRet = select(nFd+1, 0, &WriteSet, 0, &tv);

	if (nRet == 0)
	{
		return 0;
	}
	else if (nRet < 0)
	{
		return -1;
	}

	return sendto(nFd, (char*)pBuf, nSize, 0, (struct sockaddr *)&addr, nLen);
}

int socket_opt( int fd, int level, int optname, const char* optval, int optlen )
{
	return setsockopt(fd, level, optname, optval, optlen);
}


int socket_pair(int family, int type, int protocol, int sfd[2])
{
#ifndef WIN32
	return socketpair(family,type,protocol,sfd);
#else
	return win32_socketpair(family,type,protocol,sfd);
#endif
}

int socket_read(int fd, char *buf, int size)
{
#ifdef WIN32
  return recv(fd, buf, size, 0);
#else
  return read(fd, buf, size);
#endif
}

int socket_write(int fd, const char *buf, int size)
{
#ifdef WIN32
  return send(fd, buf, size, 0);
#else
  return write(fd, buf, size);
#endif
}

int socket_recvfrom(int fd, char *ip, int *port, void *buf, int size, int timeout)
{
	struct sockaddr_in from;

#ifdef WIN32
	int len = sizeof(from);
#else
	socklen_t len = sizeof(from);
#endif

	memset(&from, 0, sizeof(from));

	if (timeout < 0)
	{
		return recvfrom(fd, (char*)buf, size, 0, (struct sockaddr *)&from, &len);
	}

	int ret = 0;
	fd_set rset;
	struct timeval tv;

	tv.tv_sec = timeout/1000;
	tv.tv_usec = (timeout%1000)*1000;

	FD_ZERO(&rset);
	FD_SET(fd, &rset);

	ret = select(fd+1, &rset, 0, 0, &tv);

	if (ret == 0)
	{
		return 0;
	}
	else if (ret < 0)
	{
		return -1;
	}

	ret = recvfrom(fd, (char*)buf, size, 0, (struct sockaddr *)&from, &len);

	if (ret < 0)
	{
		return -1;
	}

	sprintf(ip, "%s", inet_ntoa(from.sin_addr));
	*port = ntohs(from.sin_port);

	return ret;
}
