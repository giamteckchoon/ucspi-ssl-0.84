#include "ip4_bit.h"
#include "byte.h"
#include "scan.h"
#include "str.h"
#include "fmt.h"

#define BITSUBSTITUTION

stralloc sanumber = {0};
char strnum[FMT_ULONG];

static int getnumber(char *buf, int len, unsigned long *u)
{
  if (!stralloc_copyb(&sanumber,buf,len)) return -1;
  if (!stralloc_0(&sanumber)) return -1;
  if (sanumber.s[scan_ulong(sanumber.s,u)]) return -1;
  return 0;
}

int getaddressasbit(char *ip, int prefix, stralloc *ip4string)
{
  int count;
  int i;
  unsigned long int num;
  int sufcount = 0;
  int pos = 0;
  int len = byte_chr(ip,str_len(ip),'/');
  int posl = byte_chr(ip,len,'.');
#ifdef BITSUBSTITUTION
  const char *letterarray = "abcdefghijklmnopqrstuvwxyz123456";
#endif
  	
  if (!stralloc_copys(ip4string,"")) return -1;
  
  for (;;) {
    num = 0;
    count = 1;
    if (getnumber(ip + pos,posl, &num) == -1) return -1;
    if (num > 255) return 2;
    
    for (i = 1; i < 9; i++) {
      if (sufcount >= prefix) return 0;
      count *= 2;
      if (num >= 256/count) {
        num -= (256/count);
#ifdef BITSUBSTITUTION
	if (!stralloc_catb(ip4string,letterarray + sufcount,1)) return -1;
#else
	if (!stralloc_cats(ip4string,"1")) return -1;
#endif
      }
      else {
	if (!stralloc_cats(ip4string,"0")) return -1;
      }
      ++sufcount;
    }    
    pos += posl + 1;
    if (pos < len+1) {
      posl = byte_chr(ip + pos + 1,len - pos - 1,'.');
      ++posl;
    }
    else return 2;
  }
  return 0;
}

