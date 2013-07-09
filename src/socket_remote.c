#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ip.h"
#include "byte.h"
#include "socket.h"

int socket_remote(int s,socket_address *sa,uint16 *port)
{
  socklen_t dummy = sizeof *sa;

  if (getpeername(s,(struct sockaddr *)sa,&dummy) == -1) return -1;
  uint16_unpack_big((char *) (sa->sa4.sin_family == AF_INET ? &sa->sa4.sin_port
							    : &sa->sa6.sin6_port),
		    port);
  return 0;
}
