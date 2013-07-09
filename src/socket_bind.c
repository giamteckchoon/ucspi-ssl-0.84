#include <sys/types.h>
#include <sys/param.h>
#include "ip.h"
#include "byte.h"
#include "socket.h"

int socket_bind(int s,struct addrinfo *ai)
{
  return bind(s,ai->ai_addr,ai->ai_addrlen);
}

int socket_bind_reuse(int s,struct addrinfo *ai)
{
  int opt = 1;
  setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);
  return socket_bind(s,ai);
}

void socket_tryreservein(int s,int size)
{
  while (size >= 1024) {
    if (setsockopt(s,SOL_SOCKET,SO_RCVBUF,&size,sizeof size) == 0) return;
    size -= (size >> 5);
  }
}
