/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef common_headers_h_included
#define common_headers_h_included

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifndef NO_SYSLOG
#include <syslog.h>
#endif
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <zlib.h>

#endif
