/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef utilities_h_included
#define utilities_h_included

unsigned long long htonull(unsigned long long h);
unsigned long long ntohull(unsigned long long n);
unsigned short int ip_checksum(unsigned char* addr, unsigned int count, unsigned int* p_running_checksum);

#endif
