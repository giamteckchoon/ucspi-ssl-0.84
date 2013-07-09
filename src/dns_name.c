#include "ip.h"
#include "str.h"

int dns_name(stralloc *out, socket_address *in) {
int rc;

  if (!stralloc_ready(out,512)) return EAI_MEMORY;
  if ((rc = getnameinfo((struct sockaddr *)in, sizeof *in, out->s, out->a, 0, 0, NI_NAMEREQD))) {
    if (rc != EAI_NONAME) return rc;
    out->len = 0;
    *out->s = 0;
  } else {
    out->len = str_chr(out->s, 0) + 1;
  }
  return 0;
}

