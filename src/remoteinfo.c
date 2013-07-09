#include <unistd.h>
#include "fmt.h"
#include "buffer.h"
#include "ip.h"
#include "socket.h"
#include "error.h"
#include "iopause.h"
#include "timeoutconn.h"
#include "remoteinfo.h"

static struct taia now;
static struct taia deadline;

static int mywrite(int fd,char *buf,int len)
{
  iopause_fd x;

  x.fd = fd;
  x.events = IOPAUSE_WRITE;
  for (;;) {
    taia_now(&now);
    iopause(&x,1,&deadline,&now);
    if (x.revents) break;
    if (taia_less(&deadline,&now)) {
      errno = error_timeout;
      return -1;
    }
  }
  return buffer_unixwrite(fd,buf,len);
}

static int myread(int fd,char *buf,int len)
{
  iopause_fd x;

  x.fd = fd;
  x.events = IOPAUSE_READ;
  for (;;) {
    taia_now(&now);
    iopause(&x,1,&deadline,&now);
    if (x.revents) break;
    if (taia_less(&deadline,&now)) {
      errno = error_timeout;
      return -1;
    }
  }
  return buffer_unixread(fd,buf,len);
}

static int doit(stralloc *out,int s,socket_address *remote,socket_address *local,unsigned int timeout)
{
  buffer b;
  char bspace[128];
  char strnum[FMT_ULONG];
  int numcolons;
  char ch;
  struct addrinfo ai = {0};
  uint16 portremote, portlocal;
  socket_address sa;

  ai.ai_addr = local;
  ai.ai_addrlen = sizeof *local;
  if (socket_bind(s,&ai) == -1) return -1;
  byte_copy(&sa, sizeof(sa), remote);
  uint16_pack_big(sa.sa4.sin_family == AF_INET ? &sa.sa4.sin_port
					       : &sa.sa6.sin6_port, 113);
  ai.ai_addr = &sa;
  if (timeoutconn(s,&sa,timeout) == -1) return -1;

  uint16_unpack_big(remote->sa4.sin_family == AF_INET ? &remote->sa4.sin_port
						      : &remote->sa6.sin6_port,
		    &portremote);
  uint16_unpack_big(local->sa4.sin_family == AF_INET ? &local->sa4.sin_port
						     : &local->sa6.sin6_port,
		    &portlocal);

  buffer_init(&b,mywrite,s,bspace,sizeof bspace);
  buffer_put(&b,strnum,fmt_ulong(strnum,portremote));
  buffer_put(&b," , ",3);
  buffer_put(&b,strnum,fmt_ulong(strnum,portlocal));
  buffer_put(&b,"\r\n",2);
  if (buffer_flush(&b) == -1) return -1;

  buffer_init(&b,myread,s,bspace,sizeof bspace);
  numcolons = 0;
  for (;;) {
    if (buffer_get(&b,&ch,1) != 1) return -1;
    if ((ch == ' ') || (ch == '\t') || (ch == '\r')) continue;
    if (ch == '\n') return 0;
    if (numcolons < 3) {
      if (ch == ':') ++numcolons;
    }
    else {
      if (!stralloc_append(out,&ch)) return -1;
      if (out->len > 256) return 0;
    }
  }
}

int remoteinfo(stralloc *out,socket_address *remote,socket_address *local,unsigned int timeout)
{
  int s;
  int r;

  if (!stralloc_copys(out,"")) return -1;

  taia_now(&now);
  taia_uint(&deadline,timeout);
  taia_add(&deadline,&now,&deadline);

  s = socket_tcp(local->sa4.sin_family, 0);
  if (s == -1) return -1;
  r = doit(out,s,remote,local,timeout);
  close(s);
  return r;
}
