// netbase-17.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "evt_loop.h"

int main()
{
    std::cout << "Hello World!\n";

    netb::evt_loop loop;


    struct event_base *base;
    struct evconnlistener *listener;
    struct event *signal_event;


    base = event_base_new();
    //event_config_new();
//     if (!base) {
//       fprintf(stderr, "Could not initialize libevent!\n");
//       return 1;
//     }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
