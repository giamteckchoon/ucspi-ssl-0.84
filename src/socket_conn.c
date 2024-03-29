#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "byte.h"
#include "socket.h"

int socket_connected(int s)
{
  struct sockaddr_in sa;
  socklen_t dummy = sizeof sa;
  char ch;

  if (getpeername(s,(struct sockaddr *) &sa,&dummy) == -1) {
    read(s,&ch,1); /* sets errno */
    return 0;
  }
  return 1;
}
