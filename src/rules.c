/** 
  @file rules.c
  @author djb, jens wehrenbrecht
  @brief Evaluates rules for IPv4, host, remeoteinfo, and IPv4/CIDR 
*/
#include "alloc.h"
#include "stralloc.h"
#include "open.h"
#include "cdb.h"
#include "rules.h"
#include "strerr.h"
#include "byte.h"
#include "ip.h"
#include "fmt.h"
#include "getln.h"
#include "ip4_bit.h"

stralloc rules_name = {0};
static stralloc remote = {0};
stralloc ipstring = {0};
int bitsize = 2;

static struct cdb c;

static const char HEX[] = "0123456789abcdef";

static int dorule(void (*callback)(char *,unsigned int))
{
  char *data;
  unsigned int datalen;

  switch(cdb_find(&c,rules_name.s,rules_name.len)) {
    case -1: return -1;
    case 0: return 0;
  }

  datalen = cdb_datalen(&c);
  data = alloc(datalen);
  if (!data) return -1;
  if (cdb_read(&c,data,datalen,cdb_datapos(&c)) == -1) {
    alloc_free(data);
    return -1;
  }

  callback(data,datalen);
  alloc_free(data);
  return 1;
}

static int doit(void (*callback)(char *,unsigned int),socket_address *sa,char *host,char *info)
{
  int r, p, v6 = 0;

  if (sa->sa4.sin_family == AF_INET) {
    if (ip_fmt(&remote, sa)) return -1;
  } else if (byte_equal(sa->sa6.sin6_addr.s6_addr, 12, V6_MAPPED_PREFIX)) {
    socket_address tmpsa = {0};
    tmpsa.sa4.sin_family = AF_INET;
    byte_copy(&tmpsa.sa4.sin_addr, 4, &sa->sa4.sin_addr);
    if (ip_fmt(&remote, &tmpsa)) return -1;
  } else {
    v6 = 1;
    if (stralloc_ready(&remote, 16*2 + 1) == -1) return -1;
    stralloc_copys(&remote, "");
    for (r = 0; r < 16; r++) {
      remote.s[remote.len++] = HEX[(sa->sa6.sin6_addr.s6_addr[r] >> 4) & 0xf];
      remote.s[remote.len++] = HEX[sa->sa6.sin6_addr.s6_addr[r] & 0xf];
    }
  }

  if (info) {
    if (!stralloc_copys(&rules_name,info)) return -1;
    if (!stralloc_cats(&rules_name,"@")) return -1;
    if (!stralloc_cat(&rules_name,&remote)) return -1;
    r = dorule(callback);
    if (r) return r;

    if (host) {
      if (!stralloc_copys(&rules_name,info)) return -1;
      if (!stralloc_cats(&rules_name,"@=")) return -1;
      if (!stralloc_cats(&rules_name,host)) return -1;
      r = dorule(callback);
      if (r) return r;
    }
  }
  
  if (!stralloc_copy(&rules_name,&remote)) return -1;
  r = dorule(callback);
  if (r) return r;

  if (host) {
    if (!stralloc_copys(&rules_name,"=")) return -1;
    if (!stralloc_cats(&rules_name,host)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (!stralloc_copy(&rules_name,&remote)) return -1;
  while (rules_name.len > 0) {
    if (v6 || rules_name.s[rules_name.len - 1] == '.') {
      r = dorule(callback);
      if (r) return r;
    }
    --rules_name.len;
  }
  
  if (sa->sa4.sin_family == AF_INET) {
    if (getaddressasbit(&sa->sa4.sin_addr,32,&ipstring) != -1) {
      for (p=33; p>1; p--) {
        if (!stralloc_copys(&rules_name,"_")) return -1;
        if (!stralloc_catb(&rules_name,ipstring.s,p)) return -1;
        r = dorule(callback);
        if (r) return r;
      }
    }
  }

  if (host) {
    while (*host) {
      if (*host == '.') {
        if (!stralloc_copys(&rules_name,"=")) return -1;
        if (!stralloc_cats(&rules_name,host)) return -1;
	r = dorule(callback);
	if (r) return r;
      }
      ++host;
    }
    if (!stralloc_copys(&rules_name,"=")) return -1;
    r = dorule(callback);
    if (r) return r;
  }
  
  rules_name.len = 0;
  return dorule(callback);
}

int rules(void (*callback)(char *,unsigned int),int fd,socket_address *sa,char *host,char *info)
{
  int r;
  cdb_init(&c,fd);
  r = doit(callback,sa,host,info);
  cdb_free(&c);
  return r;
}
