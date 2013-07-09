#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ip.h"
#include "byte.h"
#include "socket.h"

int socket_accept(int s,socket_address *sa,uint16 *port)
{
  socklen_t dummy = sizeof *sa;
  int fd;

  fd = accept(s,(struct sockaddr *)sa,&dummy);
  if (fd == -1) return -1;

  uint16_unpack_big(sa->sa4.sin_family == AF_INET ? &(sa->sa4.sin_port)
						  : &(sa->sa6.sin6_port),
		    port);

  return fd;
}
