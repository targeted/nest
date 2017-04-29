/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

/* Independent auxiliary utility functions. */

#include "utilities.h"

/* ------------------------------------------------------------------------------------- */
/* On little-endian machine, takes 0123456789ABCDEF and returns EFCDAB8967452301,
   on big-endian machine, returns 0123456789ABCDEF
*/
unsigned long long htonull(unsigned long long h)
{
#ifdef LITTLE_ENDIAN
    return (((unsigned long long)(htonl((unsigned int)(h & 0xffffffff)))) << 32) |
           ((unsigned long long)(htonl((unsigned int)(h >> 32))));
#else
    return h;
#endif
}

/* ------------------------------------------------------------------------------------- */
/* Same as above.
*/
unsigned long long ntohull(unsigned long long n)
{
    return htonull(n);
}

/* ------------------------------------------------------------------------------------- */
/* Calculates Internet checksum, used with sending/receiving hand-made ICMP/IP packets */

unsigned short int ip_checksum(unsigned char* addr, unsigned int count, unsigned int* p_running_checksum)
{

    unsigned int sum = p_running_checksum == 0 ? 0 : *p_running_checksum;

    while (count >= 2)
    {
        sum += *(unsigned short int*)addr;
        addr += 2;
        count -= 2;
    }

    /* using p_running_checksum is only valid when all the fragments except for the last have even length */

    if (p_running_checksum != 0) *p_running_checksum = sum;

    if (count > 0) sum += *addr;

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;

}

/* ------------------------------------------------------------------------------------- */
/* Empty stub for syslog */

#ifdef NO_SYSLOG
void _syslog(int priority, const char *message, ...) {}
#endif

/* ------------------------------------------------------------------------------------- */
