#ifndef SOCKET_H
#define SOCKET_H

#include "uint16.h"
#include "ip.h"

extern int socket_tcp(int,int);
extern int socket_udp(void);

extern int socket_connected(int);
extern int socket_bind(int,struct addrinfo *);
extern int socket_bind_reuse(int,struct addrinfo *);
extern int socket_listen(int,int);
extern int socket_accept(int,socket_address *,uint16 *);
extern int socket_recv4(int,char *,int,char *,uint16 *);
extern int socket_send4(int,const char *,int,const char *,uint16);
extern int socket_local(int,socket_address *,uint16 *);
extern int socket_remote(int,socket_address *,uint16 *);
extern int socket_tcpnodelay(int);
extern int socket_ipoptionskill(int);

extern void socket_tryreservein(int,int);

#endif
