#ifndef RULES_H
#define RULES_H

#include "stralloc.h"
#include "ip.h"

extern stralloc rules_name;
extern int rules(void (*)(char *,unsigned int),int,socket_address *,char *,char *);

#endif
