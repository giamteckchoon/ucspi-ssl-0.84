#ifndef IP_H
#define IP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "stralloc.h"

typedef union {
    struct sockaddr_in	sa4;
    struct sockaddr_in6	sa6;
} socket_address;

#define V6_MAPPED_PREFIX	"\0\0\0\0\0\0\0\0\0\0\377\377"

extern int ip_fmt(stralloc *out, socket_address *in);
extern int dns_name(stralloc *out, socket_address *in);

#endif
