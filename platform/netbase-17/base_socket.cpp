
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
#include <unistd.h>	/*符号常量*/
#include <fcntl.h>	/*文件控制*/
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
#include <sys/stat.h> /*文件状态*/
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
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
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
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
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
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
	socklen_t addrlen_ai;
#endif

	
#ifdef WIN32
	int addrlen_res;
#else
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
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
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
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
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
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
		 *设置socket为强制关闭
		 *close(fd)时，tcp夭折，缓存的数据
		 *丢弃。此处为了避免TIME_WAIT
		 */
		struct linger lgr;
		lgr.l_onoff = 1;
		lgr.l_linger = 0;
		setsockopt(nFd, SOL_SOCKET, SO_LINGER, (const char*)&lgr, sizeof(lgr));

		/*
		 *设置socket接收缓冲区大小
		 *UNIX下滑动窗口设置与此有关
		 *window下与此无关，默认值即可。(未亲自测试)
		 */
		int nRecvBuf  = 32*1024; /*32K*/
		setsockopt(nFd, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int));

		/*
		 *设置socket发送缓冲区大小
		 *UNIX下滑动窗口设置与此有关
		 *window下与此无关，默认值即可。(未亲自测试)
		 */
		int nSendBuf  = 32*1024; /*32K*/
		setsockopt(nFd, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));

		/*
		 *设置socket发送接受超时时间
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

	/*需清空地址族，否则，不同的网络协议，值不同*/
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	/*IPV4*/
	addr.sin_family = AF_INET; 

	/*
	 *当前socket被绑定的端口
	 *端口需要转为网络字节序
	 */
	addr.sin_port = htons(nPort); 

	/*
	 *当前socket被绑定的IP
	 *
	 *注意:inet_addr()返回32位IPV4的网络字节序
	 *地址。
	 *存在问题，因为返回值1111 1111 1111 1111为
	 *255.255.255.255，与失败值冲突，因此，很多
	 *错误不能表示。
	 */
	addr.sin_addr.s_addr = (pszIp == NULL ? htonl(INADDR_ANY) : inet_addr(pszIp)); 

	/*
	 *绑定socket到本地指定地址，
	 *随所使用的网路协议不同而不同，
	 *因此，需要第三个参数指定长度
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
	 *调用accept前，最后一个参
	 *长度必须是sockaddr_in, 否则,
	 *accept会错误
	 **/
#ifdef WIN32
	int nAddrLen = sizeof(From);
#else
	/*UNIX/Linux中需要指定socklen,64位机器int与socklen_t
	 *长度不一样*/
	socklen_t nAddrLen = sizeof(From);
#endif

	/*问题:
	 *1.accept是否有阻塞与非阻塞问题?
	 *
	 *答:socket accept有阻塞问题，若未处理的
	 *connect队列中没有未处理的连接请求，则阻塞
	 *socket下，accept会阻塞调用者，直到有connection请求到来
	 *
	 *
	 *2.若有，此处socket accept怎样处理?
	 *答: 由于存在阻塞socket问题，因此，若采取非阻塞
	 *处理需要使用select来将socket从阻塞变为非阻塞socket
	 *
	 */

	if (nTimeOut > 0)
	{		
		/*
		 *若超时值大于0，则采用非阻塞处理，一定时间内没有
		 *connection等待连接队列中，没有连接请求，则退出
		*/
		fd_set ReadSet;
		struct timeval TimeVal;

		/*获取阻塞时间*/
		TimeVal.tv_sec = nTimeOut / 1000; 
		TimeVal.tv_usec = (nTimeOut % 1000) * 1000;

		FD_ZERO(&ReadSet);
		FD_SET(nFd, &ReadSet);
		/*select指定描述符的个数而不是最大值
		 *描述符从0开始*/
		nRet = select(nFd + 1, &ReadSet, 0, 0, &TimeVal);

		/*select超时*/
		if (nRet == 0)
		{
			return 0;
		}
		else if (nRet < 0) /*socket异常*/
		{
			return -1;
		}
	}

	/*成功，返回真实的连接socket*/
	int nClientFd = (int)accept(nFd, (struct sockaddr*)&From, &nAddrLen);

	if (nClientFd != INVALID_SOCKET)
	{
		/*成功记录客户端的IP与Port*/
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
 *说明: socket中等待队列的最大长度
 *
 *@backlog: 
 *
 *listen中，backlog是为了设置等待连接队列的
 *最大长度，而不是在一个端口上同时可以进
 *行连接的数目。
 *
 *例如:backlog == 2时， 当有三个请求同时到达，
 *前两个连接请求就会被放到等待队列中，然后
 *由App依次为这些请求服务，第三个请求就被
 *拒绝了。
 *
 */
int socket_listen( int nFd, int nMax )
{
	if (nFd == INVALID_SOCKET)
	{
		return -1;
	}

	/*监听*/
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
	
	/*填充要连接的目的端地址(SVR)*/
	nAddr.sin_family = AF_INET;
	nAddr.sin_port = htons(nPort);
	nAddr.sin_addr.s_addr = inet_addr(pszIp);

	/*如果是小于0，则采用阻塞方式*/
	if (nTimeOut < 0)
	{
		/*
		 *1.对于面向连接的socket, 阻塞方式，需等到对方的返回。
		 *
		 *2.对于无连接的socket，阻塞方式中的connect,仅仅为后面的
		 *send，recv调用建立一个默认的目标地址。
		 */
		return connect(nFd, (const struct sockaddr*)&nAddr, sizeof(nAddr));
	}

	/*
	 *非阻塞方式
	 *
	 *将阻塞socket connect方式，设置为非阻塞connect
	 */
	if (socket_setnonblock(nFd) == -1)
	{
		return -1;
	}

	nRet = connect(nFd, (struct sockaddr*)&nAddr, sizeof(nAddr));

	/*
	 *非阻塞模式下，若立即连接成功，则将socket
	 *设置为阻塞方式，并返回
	 */
	if (nRet == 0)
	{
		socket_setblock(nFd);
		
		return nRet;
	}

#ifdef WIN32

	/*
	 *除非阻塞socket connect连接正常异常
	 *以外的异常，设置为阻塞退出
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

	/*MSDN: 对于非阻塞socket，连接请求不能马上完成，返回
	 *WSAEWOULDBLOCK，可以通过select查询socket是否可写
	 *通过select查询*/
	fd_set WriteSet;
	struct timeval TimeVal;

	/*获取阻塞时间*/
	TimeVal.tv_sec = nTimeOut / 1000; 
	TimeVal.tv_usec = (nTimeOut % 1000) * 1000;

	FD_ZERO(&WriteSet);
	FD_SET(nFd, &WriteSet);/*将描述符Fd加入集合*/

	/*如果Tcp协议栈收到，SVR发送过来对应次socket的应答请求，*/
	if (select(nFd + 1, 0, &WriteSet, 0, &TimeVal) > 0)
	{
		int nError = -1;
		int nLen = sizeof(int);

		/*测试fd集中的一个给定位是否是否仍处于打开状态
		 *打开指FD_SET某个fd*/
		if (FD_ISSET(nFd, &WriteSet))
		{
			/*通过接口查询socket的异常*/
			if (getsockopt(nFd, SOL_SOCKET, SO_ERROR, (char*)&nError, (socklen_t*)&nLen) < 0)
			{
				/*接口调用异常*/
				socket_setblock(nFd);
				return -1;
			}

			/*没有查询到socket异常*/
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

		/*清空set的所有bit*/
		FD_ZERO(&WriteSet);
		/*在set中开启fd的标志*/
		FD_SET(nFd, &WriteSet);

		TimeVal.tv_sec = nTimeOut/1000;
		TimeVal.tv_usec = (nTimeOut%1000)*1000;
		/*select模型最大支持1024个描述符，超过1024用poll
		 *查看当前fd是否可写*/
		nRet = select(nFd+1, NULL, &WriteSet, NULL, &TimeVal); // NULL

		/*调用select异常*/
		if (nRet < 0)
		{
			/*
			 *标准C下，由于信号中断，没写成功任何数据
			 *
			 *如果进程在一个慢系统调用(slow system call)中
			 *阻塞时，当捕获到某个信号且相应信号处理函
			 *数返回时，这个系统调用被中断，调用返回错
			 *误，设置errno为EINTR
			 */
			if (errno == EINTR)
			{
				/*如果连续三次超时，返回0*/
				nSendTimes ++;
				if (nSendTimes > 2)
				{
					return 0;
				}

				continue;
			}

			return -1;				
		}
		else if (0 == nRet) /*select超时*/
		{
			/*如果连续三次超时，返回0*/
			nSendTimes ++;
			if (nSendTimes > 2)
			{
				return 0;
			}

			continue;
		}
		else
		{
			/*开始发送*/
			if (FD_ISSET(nFd, &WriteSet))
			{

				if ((nWritten = send(nFd, p, nLeft, 0)) <= 0)
				{
					/*
					 *发送异常
					 *
					 *在linux进行非阻塞的socket接收数据时
					 *经常出现Resource temporarily unavailable，
					 *errno代码为11(EAGAIN)，这表明你在非
					 *阻塞模式下调用了阻塞操作，在该操
					 *作没有完成就返回这个错误，这个错
					 *误不会破坏socket的同步
					 */
					if ((errno == EINTR) || (errno == EAGAIN))			
					{
						nWritten = 0;

						nSendTimes ++;
						if (nSendTimes > 2) // 如果连续三次发送不出去，返回0
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
*Description: 接受数据
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

	/*阻塞模式，直接接受数据*/
	if (nTimeOut < 0)
	{
		return recv(nFd, (char*)pBuf, nSize, 0);
	}


	/*非阻塞模式，用select查询到再接收*/
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

	/*阻塞下*/
	if (nTimeOut < 0)
	{
		return sendto(nFd, (char*)pBuf, nSize, 0, (struct sockaddr *)&addr, nLen);
	}

	/*非阻塞下*/
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
