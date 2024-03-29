#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include "ucspissl.h"
#include "uint16.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "getln.h"
#include "error.h"
#include "strerr.h"
#include "sgetopt.h"
#include "pathexec.h"
#include "socket.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ccafile.h"
#include "auto_dhfile.h"
#include "auto_certfile.h"
#include "auto_certchainfile.h"
#include "auto_keyfile.h"
#include "auto_ciphers.h"
#include "fmt.h"

int verbosity = 1;
int flagkillopts = 1;
int flagdelay = 0;
const char *banner = "";
int flagremoteinfo = 0;
int flagremotehost = 1;
int flagparanoid = 0;
int flagclientcert = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
int flagsslwait = 0;
unsigned long timeout = 26;
unsigned long ssltimeout = 26;
unsigned int progtimeout = 3600;

static stralloc tcpremoteinfo;

uint16 localport;
char localportstr[FMT_ULONG];
socket_address localaddr = {0};
static stralloc localhostsa = {0}, localipsa = {0};
const char *localhost = 0;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
socket_address remoteaddr = {0};
static stralloc remotehostsa = {0}, remoteipsa = {0};
char *remotehost = 0;
char *verifyhost = 0;

unsigned long uid = 0;
unsigned long gid = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

static stralloc tmp;

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certchainfile = auto_certchainfile;
const char *certfile = auto_certfile;
const char *keyfile = auto_keyfile;
stralloc password = {0};
int match = 0;
const char *cafile = auto_cafile;
const char *ccafile = auto_ccafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
int verifydepth = 1;
const char *dhfile = auto_dhfile;
int rsalen = 1024;

char * const *prog;

int pi[2];
int po[2];
int pt[2];

stralloc envsa = {0};

X509 *cert;
char buf[SSL_NAME_LEN];

#define FATAL "sslserver: fatal: "


/* ---------------------------- child */

#define DROP "sslserver: warning: dropping SSL connection, "

int flagdeny = 0;
int flagallownorules = 0;
const char *fnrules = 0;

void drop_nomem(void)
{
  strerr_die2sys(111,DROP,"out of memory");
}
void cats(const char *s)
{
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(const char *ch)
{
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(const char *s) {
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t) {
  if (!pathexec_env(s,t)) drop_nomem();
}
int error_warn(const char *x) {
  if (!x) return 0;
  strerr_warn2("sslserver: ",x,0);
  return 0;
}
void drop_rules(void) {
  strerr_die4sys(111,DROP,"unable to read ",fnrules,": ");
}

void found(char *data,unsigned int datalen) {
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	flagdeny = 1;
	break;
      case '+':
	split = str_chr(data + 1,'=');
	if (data[1 + split] == '=') {
	  data[1 + split] = 0;
	  env(data + 1,data + 1 + split + 1);
	}
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit(int t) {
  int j;
  SSL *ssl;
  int wstat;
  int sslctl[2];
  char *s;
  unsigned long tmp_long;
  char ssl_cmd;
  stralloc ssl_env = { 0 };
  int bytesleft;
  char envbuf[8192];
  int childpid;
  
  if (pipe(pi) == -1) strerr_die2sys(111,DROP,"unable to create pipe: ");
  if (pipe(po) == -1) strerr_die2sys(111,DROP,"unable to create pipe: ");
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sslctl) == -1) strerr_die2sys(111,DROP,"unable to create socketpair: ");
 
  if ((j = ip_fmt(&remoteipsa,&remoteaddr)))
    strerr_die3x(111,DROP,"unable to print remote ip",gai_strerror(j));

  if (flagremotehost) {
    if (dns_name(&remotehostsa,&remoteaddr) == 0)
      if (remotehostsa.len) {
	if (flagparanoid) {
	  struct addrinfo *reverse, hints = {0};
	  verifyhost = remoteipsa.s;
	  hints.ai_family = remoteaddr.sa4.sin_family;
	  if (remoteaddr.sa6.sin6_family == AF_INET6) {
	    hints.ai_flags = AI_V4MAPPED | AI_ALL;
	  }
	  if (getaddrinfo(remotehostsa.s, NULL, &hints, &reverse) == 0) {
	    hints.ai_next = reverse;
	    while (hints.ai_next) {
	      if (hints.ai_next->ai_family == AF_INET
		  && remoteaddr.sa4.sin_family == AF_INET
		  && byte_equal(&remoteaddr.sa4.sin_addr, 4, &((struct sockaddr_in*) hints.ai_next->ai_addr)->sin_addr)
		  || hints.ai_next->ai_family == AF_INET6
		     && remoteaddr.sa6.sin6_family == AF_INET6
		     && byte_equal(remoteaddr.sa6.sin6_addr.s6_addr, 16,
				   &((struct sockaddr_in6*) hints.ai_next->ai_addr)->sin6_addr.s6_addr)) {
		flagparanoid = 0;
		break;
	      }
	      hints.ai_next = hints.ai_next->ai_next;
	    }
	    freeaddrinfo(reverse);
	  }
	}
	if (!flagparanoid) {
	  remotehost = remotehostsa.s;
	  verifyhost = remotehostsa.s;
	}
      }
  }

  switch(childpid=fork()) {
    case -1:
      strerr_die2sys(111,DROP,"unable to fork: ");
    case 0:
      /* Child */
      close(sslctl[0]);
      break;
    default:
      /* Parent */
      
      close(pi[0]); close(po[1]); close(sslctl[1]);

      if ((s=env_get("SSL_CHROOT")))
        if (chroot(s) == -1) {
          kill(childpid, SIGTERM);
          strerr_die2x(111,DROP,"unable to chroot");
        }
      
      if ((s=env_get("SSL_GID"))) {
        scan_ulong(s,&tmp_long);
        gid = tmp_long;
      }
      if (gid) if (prot_gid(gid) == -1) {
        kill(childpid, SIGTERM);
        strerr_die2sys(111,FATAL,"unable to set gid: ");
      }

      if ((s=env_get("SSL_UID"))) {
        scan_ulong(s,&tmp_long);
        uid = tmp_long;
      }
      if (uid)
        if (prot_uid(uid) == -1) {
          kill(childpid, SIGTERM);
          strerr_die2sys(111,FATAL,"unable to set uid: ");
        }

      /* Read the TLS command socket.  This will block until/unless
       * TLS is requested.
       */
      if (read(sslctl[0],&ssl_cmd,1) == 1) {
        ssl = ssl_new(ctx,t);
        if (!ssl) {
          kill(childpid, SIGTERM);
          strerr_die2x(111,DROP,"unable to create SSL instance");
        }
        if (ndelay_on(t) == -1) {
          kill(childpid, SIGTERM);
          strerr_die2sys(111,DROP,"unable to set socket options: ");
        }
        if (ssl_timeoutaccept(ssl,ssltimeout) == -1) {
          kill(childpid, SIGTERM);
          strerr_die3x(111,DROP,"unable to accept SSL: ",ssl_error_str(ssl_errno));
        }
      }
        
      if (verbosity >= 2) {
        strnum[fmt_ulong(strnum,getpid())] = 0;
        strerr_warn3("sslserver: ssl ",strnum," accept ",0);
      }
        
      if (flagclientcert) {
        switch(ssl_verify(ssl,verifyhost)) {
          case -1:
	    kill(childpid, SIGTERM);
            strerr_die2x(111,DROP,"unable to verify client certificate");
          case -2:
	    kill(childpid, SIGTERM);
            strerr_die2x(111,DROP,"no client certificate");
          case -3:
	    kill(childpid, SIGTERM);
            strerr_die3x(111,DROP,"certificate name does not match client fqdn: ",verifyhost);
          default: break;
        }
      }
      
      if (ssl_cmd == 'Y') {
        ssl_server_env(ssl, &ssl_env);
        if(!stralloc_0(&ssl_env)) drop_nomem(); /* Add another NUL */
        env("SSLCTL",ssl_env.s); 

        for(bytesleft = ssl_env.len; bytesleft>0; bytesleft-=j)
          if ( (j=write(sslctl[0], ssl_env.s, bytesleft)) < 0) {
            kill(childpid, SIGTERM);
            strerr_die2sys(111, FATAL, "unable to write SSL environment: ");
          }
      }

      if (ssl_cmd == 'Y' || ssl_cmd == 'y') {
        if (ssl_io(ssl,pi[1],po[0],progtimeout) != 0) {
          kill(childpid, SIGTERM);
          strerr_die3x(111,DROP,"unable to speak SSL: ",ssl_error_str(ssl_errno));
        }
        if (wait_nohang(&wstat) > 0)
          _exit(wait_exitcode(wstat)); 
        ssl_close(ssl);
      }
      kill(childpid, SIGTERM);
      _exit(0);
  }

  /* Child-only below this point */

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn4("sslserver: pid ",strnum," from ",remoteipsa.s,0);
  }

  if (socket_local(t,&localaddr,&localport) == -1)
    strerr_die2sys(111,DROP,"unable to get local address: ");

  if ((j = ip_fmt(&localipsa,&localaddr)))
    strerr_die3x(111,DROP,"unable to print local address: ",gai_strerror(j));
  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (!localhost)
    if (dns_name(&localhostsa,&localaddr) == 0)
      if (localhostsa.len) {
	if (!stralloc_0(&localhostsa)) drop_nomem();
	localhost = localhostsa.s;
      }
  /* If remoteipsa.s contain ':' colon character will assume it is IPv6 */
  if (byte_chr(remoteipsa.s, remoteipsa.len, ':') < remoteipsa.len)
    env("PROTO","SSL6");
  else
    env("PROTO","SSL");
  env("SSLLOCALIP",localipsa.s);
  env("SSLLOCALPORT",localportstr);
  env("SSLLOCALHOST",localhost);
  if (flagtcpenv) {
    env("TCPLOCALIP",localipsa.s);
    env("TCPLOCALPORT",localportstr);
    env("TCPLOCALHOST",localhost);
  }

  env("SSLREMOTEIP",remoteipsa.s);
  env("SSLREMOTEPORT",remoteportstr);
  env("SSLREMOTEHOST",remotehost);
  if (flagtcpenv) {
    env("TCPREMOTEIP",remoteipsa.s);
    env("TCPREMOTEPORT",remoteportstr);
    env("TCPREMOTEHOST",remotehost);
  }

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,&remoteaddr,&localaddr,timeout) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }
  env("SSLREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);
  if (flagtcpenv)
    env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

  if (fnrules) {
    int fdrules;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != error_noent) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,&remoteaddr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1)
	drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,"sslserver: ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipsa.s);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipsa.s);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) _exit(100);

  if (gid) if (prot_gid(gid) == -1)
    strerr_die2sys(111,FATAL,"unable to set gid: ");
  if (uid) if (prot_uid(uid) == -1)
    strerr_die2sys(111,FATAL,"unable to set uid: ");

  close(pi[1]); close(po[0]); close(sslctl[0]);

  sig_uncatch(sig_child);
  sig_unblock(sig_child);
  sig_uncatch(sig_term);
  sig_uncatch(sig_pipe);

  if (fcntl(sslctl[1],F_SETFD,0) == -1)
    strerr_die2sys(111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,sslctl[1])]=0;
  env("SSLCTLFD",strnum);

  if (fcntl(pi[0],F_SETFD,0) == -1)
    strerr_die2sys(111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,pi[0])]=0;
  env("SSLREADFD",strnum);

  if (fcntl(po[1],F_SETFD,0) == -1)
    strerr_die2sys(111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,po[1])]=0;
  env("SSLWRITEFD",strnum);

  if (flagsslwait) {
    if (fd_copy(0,t) == -1)
      strerr_die2sys(111,DROP,"unable to set up descriptor 0: ");
    if (fd_copy(1,t) == -1)
      strerr_die2sys(111,DROP,"unable to set up descriptor 1: ");
  } else {
    if (fd_move(0,pi[0]) == -1)
      strerr_die2sys(111,DROP,"unable to set up descriptor 0: ");
    if (fd_move(1,po[1]) == -1)
      strerr_die2sys(111,DROP,"unable to set up descriptor 1: ");
  }

  if (flagkillopts)
    socket_ipoptionskill(t);
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (*banner) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof bspace);
    if (buffer_putsflush(&b,banner) == -1)
      strerr_die2sys(111,DROP,"unable to print banner: ");
  }

  if (!flagsslwait) {
    ssl_cmd = flagsslenv ? 'Y' : 'y';
    if (write(sslctl[1], &ssl_cmd, 1) < 1)
      strerr_die2sys(111,DROP,"unable to start SSL: ");
    if (flagsslenv) {
      while ((j=read(sslctl[1],envbuf,8192)) > 0) {
        stralloc_catb(&ssl_env,envbuf,j);
        if (ssl_env.len >= 2 && ssl_env.s[ssl_env.len-2]==0 && ssl_env.s[ssl_env.len-1]==0)
          break;
      }
      if (j < 0)
        strerr_die2sys(111,DROP,"unable to read SSL environment: ");
      pathexec_multienv(&ssl_env);
    }
  }
      
  pathexec(prog);
  strerr_die4sys(111,DROP,"unable to run ",*prog,": ");
}



/* ---------------------------- parent */

void usage(void)
{
  strerr_warn1("\
sslserver: usage: sslserver \
[ -1346UXpPhHrRoOdDqQviIeEsSnN ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -T ssltimeout ] \
[ -w progtimeout ] \
host port program",0);
  _exit(100);
}

unsigned long limit = 40;
unsigned long numchildren = 0;

int flag1 = 0;
int flag3 = 0;
unsigned long backlog = 20;

void printstatus(void)
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strerr_warn4("sslserver: status: ",strnum,"/",strnum2,0);
}

void sigterm(void)
{
  _exit(0);
}

void sigchld(void) {
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      strerr_warn4("sslserver: end ",strnum," status ",strnum2,0);
    }
    if (numchildren) --numchildren; printstatus();
  }
}

void read_passwd(void) {
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof bspace);
    if (getln(&b,&password,&match,'\0') == -1)
      strerr_die2sys(111,FATAL,"unable to read password: ");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buff,int size,int rwflag,void *userdata) {
  if (size < password.len)
    strerr_die2x(111,FATAL,"password too long");

  byte_copy(buff,password.len,password.s);
  return password.len;
}

int main(int argc,char * const *argv) {
  const char *hostname;
  int opt;
  char *x;
  unsigned long u;
  int s;
  int t;
  int flagv4 = 1, flagv6 = 1, rc;
  struct addrinfo *localai = NULL, hints = {0}, *ai;
 
  while ((opt = getopt(argc,argv,"dDvqQhHrR1UXx:t:T:u:g:l:b:B:c:pPoO3IiEeSsw:nN46")) != opteof)
    switch(opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'B': banner = optarg; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'p': flagparanoid = 1; break;
      case 'O': flagkillopts = 1; break;
      case 'o': flagkillopts = 0; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'T': scan_ulong(optarg,&ssltimeout); break;
      case 'w': scan_uint(optarg,&progtimeout); break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
		x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case '1': flag1 = 1; break;
      case 'l': localhost = optarg; break;
      case '3': flag3 = 1; break;
      case 'I': flagclientcert = 0; break;
      case 'i': flagclientcert = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'n': flagsslwait = 1; break;
      case 'N': flagsslwait = 0; break;
      case '4': flagv6 = 0; break;
      case '6': flagv4 = 0; break;
      default: usage();
    }
  if (flagv4 == flagv6) { flagv4 = flagv6 = 1; }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  hostname = *argv++;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = NULL;
  if (str_equal(hostname,"0")) hostname = NULL;

  x = *argv++;
  if (!x) usage();
  prog = argv;
  if (!*argv) usage();

  hints.ai_family = flagv4 == flagv6 ? AF_UNSPEC : flagv4 ? AF_INET : AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if ((rc = getaddrinfo(hostname, x, &hints, &localai))) {
    strerr_die(111,FATAL "unable to figure out address for ", hostname ? hostname : "0",
		" ",x,": ",gai_strerror(rc),0);
  }
  if (!localai) {
    strerr_die2x(111,FATAL,"address not found");
  }

  if (x = env_get("VERIFYDEPTH")) {
    scan_ulong(x,&u);
    verifydepth = u;
  }

  if (x = env_get("CAFILE")) cafile = x;
  if (cafile && str_equal(cafile,"")) cafile = 0;

  if (x = env_get("CCAFILE")) ccafile = x;
  if (ccafile && str_equal(ccafile,"")) ccafile = 0;
  if (!flagclientcert) ccafile = 0;

  if (x = env_get("CADIR")) cadir = x;
  if (cadir && str_equal(cadir,"")) cadir= 0;

  if (x = env_get("CERTCHAINFILE")) certchainfile = x;
  if (certchainfile && str_equal(certchainfile,"")) certchainfile = 0;

  if (x = env_get("CERTFILE")) certfile = x;
  if (certfile && str_equal(certfile,"")) certfile = 0;

  if (x = env_get("KEYFILE")) keyfile = x;
  if (keyfile && str_equal(keyfile,"")) keyfile = 0;

  if (x = env_get("DHFILE")) dhfile = x;
  if (dhfile && str_equal(dhfile,"")) dhfile = 0;

  if (x = env_get("CIPHERS")) ciphers = x;
  if (ciphers && str_equal(ciphers,"")) ciphers = 0;

  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);

  for (ai = localai; ai; ai = ai->ai_next) { 
    s = socket_tcp(ai->ai_family, ai->ai_protocol);
    if (s == -1)
      strerr_die2sys(111,FATAL,"unable to create socket: ");

    if (socket_bind_reuse(s,ai) == -1)
      strerr_die2sys(111,FATAL,"unable to bind: ");

    if (socket_local(s,&localaddr,&localport) == -1)
      strerr_die2sys(111,FATAL,"unable to get local address: ");
    if (socket_listen(s,backlog) == -1)
      strerr_die2sys(111,FATAL,"unable to listen: ");
    break;
  }
  freeaddrinfo(localai); localai = NULL;
  ndelay_off(s);

  localportstr[fmt_ulong(localportstr,localport)] = 0;
  if (flag1) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof bspace);
    buffer_puts(&b,localportstr);
    buffer_puts(&b,"\n");
    buffer_flush(&b);
  }
 
  if (flag3) read_passwd();

  ctx = ssl_server();
  ssl_errstr();
  if (!ctx) strerr_die2x(111,FATAL,"unable to create SSL context");

  if (certchainfile) {
    switch (ssl_chainfile(ctx,certchainfile,keyfile,passwd_cb)) {
      case -1: strerr_die2x(111,FATAL,"unable to load certificate chain file");
      case -2: strerr_die2x(111,FATAL,"unable to load key");
      case -3: strerr_die2x(111,FATAL,"key does not match certificate");
      default: break;
    }
  } 
  else {  
    switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
      case -1: strerr_die2x(111,FATAL,"unable to load certificate");
      case -2: strerr_die2x(111,FATAL,"unable to load key");
      case -3: strerr_die2x(111,FATAL,"key does not match certificate");
      default: break;
    }
  }

  if (!ssl_ca(ctx,cafile,cadir,verifydepth))
    strerr_die2x(111,FATAL,"unable to load CA list");

  if (!ssl_cca(ctx,ccafile))
    strerr_die2x(111,FATAL,"unable to load client CA list");

  if (!ssl_params(ctx,dhfile,rsalen))
    strerr_die2x(111,FATAL,"unable to set DH/RSA parameters");

  if (!ssl_ciphers(ctx,ciphers))
    strerr_die2x(111,FATAL,"unable to set cipher list");

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strnum2[fmt_ulong(strnum2,rsalen)] = 0;
    strerr_warn4("sslserver: cafile ",strnum," ",cafile,0);
    strerr_warn4("sslserver: ccafile ",strnum," ",ccafile,0);
    strerr_warn4("sslserver: cadir ",strnum," ",cadir,0);
    strerr_warn4("sslserver: chainfile ",strnum," ",certchainfile,0);
    strerr_warn4("sslserver: cert ",strnum," ",certfile,0);
    strerr_warn4("sslserver: key ",strnum," ",keyfile,0);
    strerr_warn6("sslserver: param ",strnum," ",dhfile," ",strnum2,0);
  }

  close(0); open_read("/dev/null");
  close(1); open_append("/dev/null");

  printstatus();
 
  for (;;) {
    while (numchildren >= limit) sig_pause();

    sig_unblock(sig_child);
    t = socket_accept(s,&remoteaddr,&remoteport);
    sig_block(sig_child);

    if (t == -1) continue;
    ++numchildren; printstatus();
 
    switch(fork()) {
      case 0:
        close(s);
        doit(t);
	strerr_die4sys(111,DROP,"unable to run ",*argv,": ");
      case -1:
        strerr_warn2(DROP,"unable to fork: ",&strerr_sys);
        --numchildren; printstatus();
    }
    close(t);
  }
}

/* taken from 0.68 */
char *ssl_error_str(int e)
{
  SSL_load_error_strings();
  return ERR_error_string(e,0);
}

