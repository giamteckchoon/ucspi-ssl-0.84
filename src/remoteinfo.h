#ifndef REMOTEINFO_H
#define REMOTEINFO_H

#include "stralloc.h"
#include "uint16.h"
#include "ip.h"

extern int remoteinfo(stralloc *,socket_address *,socket_address *,unsigned int);

#endif
