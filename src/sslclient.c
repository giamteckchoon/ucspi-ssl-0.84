#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "ucspissl.h"
#include "sig.h"
#include "exit.h"
#include "sgetopt.h"
#include "uint16.h"
#include "fmt.h"
#include "scan.h"
#include "str.h"
#include "ip.h"
#include "uint16.h"
#include "socket.h"
#include "fd.h"
#include "stralloc.h"
#include "buffer.h"
#include "getln.h"
#include "error.h"
#include "strerr.h"
#include "pathexec.h"
#include "timeoutconn.h"
#include "remoteinfo.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ciphers.h"
#include "byte.h"
#include "ndelay.h"
#include "wait.h"

#define FATAL "sslclient: fatal: "
#define CONNECT "sslclient: unable to connect to "

void nomem(void) {
  strerr_die2x(111,FATAL,"out of memory");
}
void env(const char *s,const char *t) {
  if (!pathexec_env(s,t)) nomem();
}
int error_warn(const char *x) {
  if (!x) return 0;
  strerr_warn2("sslclient: ",x,0);
  return 0;
}
void usage(void) {
  strerr_die1x(100,"sslclient: usage: sslclient \
[ -346hHrRdDqQveEsSnNxX ] \
[ -i localip ] \
[ -p localport ] \
[ -T timeoutconn ] \
[ -l localname ] \
[ -t timeoutinfo ] \
[ -a cafile ] \
[ -A cadir ] \
[ -c certfile ] \
[ -z ciphers ] \
[ -k keyfile ] \
[ -V verifydepth ] \
[ -w progtimeout ] \
host port program");
}

int verbosity = 1;
int flagdelay = 0;
int flagremoteinfo = 1;
int flagremotehost = 1;
int flag3 = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
unsigned long itimeout = 26;
unsigned long ctimeout[2] = { 2, 58 };
unsigned int progtimeout = 3600;

const char *forcelocal = 0;

socket_address local, remote;

char *hostname;
int flagname = 1;
int flagservercert = 1;
static stralloc moreaddresses;

static stralloc tmp;
char strnum[FMT_ULONG];
static stralloc ipstr;

char seed[128];

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certfile = 0;
const char *keyfile = 0;
const char *cafile = auto_cafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
stralloc password = {0};
int match = 0;
int verifydepth = 1;

int pi[2];
int po[2];
int pt[2];

void read_passwd() {
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof bspace);
    if (getln(&b,&password,&match,'\0') == -1)
      strerr_die2sys(111,FATAL,"unable to read password: ");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buf,int size,int rwflag,void *userdata) {
  if (size < password.len)
    strerr_die2x(111,FATAL,"password too long");

  byte_copy(buf,password.len,password.s);
  return password.len;
}

int main(int argc,char * const *argv) {
  unsigned long u;
  int opt;
  const char *x, *portname, *localname = NULL, *portlocal = NULL;
  int j;
  int s;
  int cloop;
  SSL *ssl;
  int wstat;
  struct addrinfo *to_bind = NULL, *to_connect = NULL, hints = {0}, *bindme;
  uint16 port;

  close(6);
  close(7);
  sig_ignore(sig_pipe);
 
  hints.ai_family = AF_UNSPEC;
  while ((opt = getopt(argc,argv,"dDvqQhHrRi:p:t:T:l:a:A:c:z:k:V:3eEsSnN0xXw:46")) != opteof)
    switch(opt) {
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'l': forcelocal = optarg; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&itimeout); break;
      case 'T': j = scan_ulong(optarg,&ctimeout[0]);
		if (optarg[j] == '+') ++j;
		scan_ulong(optarg + j,&ctimeout[1]);
		break;
      case 'w': scan_uint(optarg,&progtimeout); break;
      case 'i': localname = optarg; break;
      case 'p': portlocal = optarg; break;
      case 'a': cafile = optarg; break;
      case 'A': cadir = optarg; break;
      case 'c': certfile = optarg; break;
      case 'z': ciphers = optarg; break;
      case 'k': keyfile = optarg; break;
      case 'V': scan_ulong(optarg,&u); verifydepth = u; break;
      case '3': flag3 = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'N': flagname = 0; break;
      case 'n': flagname = 1; break;
      case 'x': flagservercert = 1; break;
      case 'X': flagservercert = 0; break;
      case '4': hints.ai_family = AF_INET; break;
      case '6': hints.ai_family = AF_INET6; break;
      default: usage();
    }
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;

  hostname = *argv;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "127.0.0.1";
  if (str_equal(hostname,"0")) hostname = "127.0.0.1";
  j = strlen(hostname);
  if (*hostname == '[' && hostname[j-1] == ']') {
    hostname[j-1] = 0;
    hostname++;
  }

  portname = *++argv;
  if (!portname) usage();

  if (flag3) read_passwd();

  if (cafile && str_equal(cafile,"")) cafile = 0;
  if (cadir && str_equal(cadir,"")) cadir= 0;
  if (ciphers && str_equal(ciphers,"")) ciphers= 0;

  if (certfile && str_equal(certfile,"")) certfile = 0;
  if (keyfile && str_equal(keyfile,"")) keyfile = 0;

  if (!*++argv) usage();

  hints.ai_socktype = SOCK_STREAM;
  if (hints.ai_family == AF_UNSPEC) {
    hints.ai_flags |= AI_ADDRCONFIG | AI_V4MAPPED;
  }
  if (localname || portlocal) {
    errno = getaddrinfo(localname, portlocal, &hints, &to_bind);
    if (errno)
      strerr_die5x(111,FATAL,"temporarily unable to figure out IP address for ",localname,": ",gai_strerror(errno));
    if (!to_bind)
      strerr_die5x(111,FATAL,"no address for ",localname?localname:"''","/",portlocal?portlocal:"0");
  }

  errno = getaddrinfo(hostname, portname, &hints, &to_connect);
  if (errno)
    strerr_die5x(111,FATAL,"temporarily unable to figure out IP address for ",hostname,": ",gai_strerror(errno));
  if (!to_connect)
    strerr_die5x(111,FATAL,"no address for ",hostname,"/",portname);
 
  if (!to_connect->ai_next) {
    ctimeout[0] += ctimeout[1];
    ctimeout[1] = 0;
  }

  s = -1;
  if (!stralloc_copys(&moreaddresses,"")) nomem();
  for (cloop = 0;cloop < 2;++cloop) {
    for (j=0, hints.ai_next = to_connect; hints.ai_next; hints.ai_next = hints.ai_next->ai_next, j++) {
      bindme = to_bind;
      while (bindme && bindme->ai_family != hints.ai_next->ai_family)
       bindme = bindme->ai_next;
      if (!bindme && to_bind) { continue; }
      if (cloop && !moreaddresses.s[j]) { continue; }
      if (hints.ai_next->ai_family > AF_MAX) { continue; }
      s = socket_tcp(hints.ai_next->ai_family, hints.ai_next->ai_protocol);
      if (s == -1)
        strerr_die2sys(111,FATAL,"unable to create socket: ");
      if (bindme && socket_bind(s,bindme) == -1)
        strerr_die2sys(111,FATAL,"unable to bind socket: ");
      byte_copy(&remote, hints.ai_next->ai_addrlen, hints.ai_next->ai_addr);
      if (timeoutconn(s,&remote,ctimeout[cloop]) == 0)
        goto CONNECTED;
      close(s);
      if (!cloop && ctimeout[1] && (errno == error_timeout)) {
	if (!stralloc_catb(&moreaddresses,"\001",1)) nomem();
      }
      else {
	if (!stralloc_catb(&moreaddresses,"",1)) nomem();
	uint16_unpack_big(remote.sa4.sin_family == AF_INET ? &(remote.sa4.sin_port)
							   : &(remote.sa6.sin6_port),
			  &port);
	strnum[fmt_ulong(strnum,port)] = 0;
	if ((opt = ip_fmt(&ipstr,(socket_address *) hints.ai_next->ai_addr)))
	  strerr_die3x(111, FATAL, "unable to print local ip: ",gai_strerror(opt));
        strerr_warn5(CONNECT,ipstr.s," port ",strnum,": ",&strerr_sys);
      }
    }
  }

  _exit(111);

  CONNECTED:

  if (socket_local(s,&local,&port) == -1)
    strerr_die2sys(111,FATAL,"unable to get local address: ");

  strnum[fmt_ulong(strnum,port)] = 0;
  env("SSLLOCALPORT",strnum);
  if (flagtcpenv) env("TCPLOCALPORT",strnum);
  if (ip_fmt(&ipstr,&local)) nomem();
  env("SSLLOCALIP",ipstr.s);
  if (flagtcpenv) env("TCPLOCALIP",ipstr.s);

  x = forcelocal;
  if (!x)
    if (dns_name(&tmp,&local) == 0) {
      x = tmp.s;
    }
  env("SSLLOCALHOST",x);
  if (flagtcpenv) env("TCPLOCALHOST",x);

  if (socket_remote(s,&remote,&port) == -1)
    strerr_die2sys(111,FATAL,"unable to get remote address: ");

  strnum[fmt_ulong(strnum,port)] = 0;
  env("SSLREMOTEPORT",strnum);
  if (flagtcpenv) env("TCPREMOTEPORT",strnum);
  if (ip_fmt(&ipstr,&remote)) nomem();
  env("SSLREMOTEIP",ipstr.s);
  /* If ipstr.s contain ':' colon character will assume it is IPv6 */
  if (byte_chr(ipstr.s, ipstr.len, ':') < ipstr.len)
    env("PROTO","SSL6");
  else
    env("PROTO","SSL");
  if (flagtcpenv) env("TCPREMOTEIP",ipstr.s);
  if (verbosity >= 2)
    strerr_warn4("sslclient: connected to ",ipstr.s," port ",strnum,0);

  x = 0;
  if (flagremotehost)
    if (dns_name(&tmp,&remote) == 0) {
      x = tmp.s;
    }
  env("SSLREMOTEHOST",x);
  if (flagtcpenv) env("TCPREMOTEHOST",x);

  x = 0;
  if (flagremoteinfo)
    if (remoteinfo(&tmp,&remote,&local,itimeout) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLREMOTEINFO",x);
  if (flagtcpenv) env("TCPREMOTEINFO",x);

  ctx = ssl_client();
  ssl_errstr();
  if (!ctx)
    strerr_die2x(111,FATAL,"unable to create SSL context");

  switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
      case -1: strerr_die2x(111,FATAL,"unable to load certificate");
      case -2: strerr_die2x(111,FATAL,"unable to load key pair");
      case -3: strerr_die2x(111,FATAL,"key does not match certificate");
      default: break;
  }
  
  if (!ssl_ca(ctx,cafile,cadir,verifydepth))
    strerr_die2x(111,FATAL,"unable to load CA list");

  if (!ssl_ciphers(ctx,ciphers))
    strerr_die2x(111,FATAL,"unable to set cipher list");

  ssl = ssl_new(ctx,s);
  if (!ssl) strerr_die2x(111,FATAL,"unable to create SSL instance");

  for (cloop = 0;cloop < 2;++cloop) {
    if (!ssl_timeoutconn(ssl,ctimeout[cloop])) goto SSLCONNECTED;
    if (!cloop && ctimeout[1]) continue;
    strerr_warn2(FATAL,"unable to SSL connect:",&strerr_sys);
    ssl_error(error_warn);
  }

  _exit(111);

  SSLCONNECTED:

  ndelay_off(s);

  if (verbosity >= 2)
    strerr_warn1("sslclient: ssl connect",0);

  if (flagservercert)
    switch(ssl_verify(ssl,flagname ? hostname : 0)) {
      case -1:
	strerr_die2x(111,FATAL,"unable to verify server certificate");
      case -2:
	strerr_die2x(111,FATAL,"no server certificate");
      case -3:
	strerr_die3x(111,FATAL,"certificate name does not match server hostname: ",hostname);
      default: break;
    }

  if (!flagdelay)
    socket_tcpnodelay(s); /* if it fails, bummer */

  if (pipe(pi) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
  if (pipe(po) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
  if (pi[0] == 7) {
    if (pipe(pt) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
    close(pi[0]); close(pi[1]);
    pi[0] = pt[0]; pi[1] = pt[1];
  }
  if (po[1] == 6) {
    if (pipe(pt) == -1) strerr_die2sys(111,FATAL,"unable to create pipe: ");
    close(po[0]); close(po[1]);
    po[0] = pt[0]; po[1] = pt[1];
  }

  switch(opt = fork()) {
    case -1:
      strerr_die2sys(111,FATAL,"unable to fork: ");
    case 0:
      break;
    default:
      close(pi[0]); close(po[1]);
      if (ssl_io(ssl,pi[1],po[0],progtimeout)) {
	strerr_warn2(FATAL,"unable to speak SSL:",&strerr_sys);
	ssl_error(error_warn);
	ssl_close(ssl);
	wait_pid(&wstat,opt);
	_exit(111);
      }
      ssl_close(ssl);
      if (wait_pid(&wstat,opt) > 0)
	_exit(wait_exitcode(wstat));
      _exit(0);
  }
  ssl_close(ssl); close(pi[1]); close(po[0]);

  if (flagsslenv && !ssl_client_env(ssl,0)) nomem();

  if (fd_move(6,pi[0]) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 6: ");
  if (fd_move(7,po[1]) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 7: ");
  sig_uncatch(sig_pipe);

  pathexec(argv);
  strerr_die4sys(111,FATAL,"unable to run ",*argv,": ");
  return 0; /* never happens, but avoids compile warning */
}
