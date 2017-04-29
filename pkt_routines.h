/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef pkt_routines_h_included
#define pkt_routines_h_included

#include "common_headers.h"

#define ZALLOC_COUNT 16        /* number of statically allocated buffers for use with zlib */
#define ZALLOC_CHUNK 65536     /* size of each allocated buffer */

extern int zlib_compression_level;                              /* value in range 0 to 9 specified in -z passed to deflateInit */
extern unsigned char zalloc_buf[ZALLOC_CHUNK * ZALLOC_COUNT];   /* statically allocated pool of buffers used */
extern int zalloc_map[ZALLOC_COUNT];                            /* for zlib memory allocations in zalloc()/zfree() */

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer where VPN packet is being assembled, the size of that buffer,
   wipes packet header. Returns 0 if OK, !0 otherwise.
*/
int initialize_packet(unsigned char* pkt_buf, unsigned int pkt_buf_size);

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer where VPN packet is being assembled, the size of that buffer,
   and packet's offset and length to be stored in the new tailer. Hangs the new tailer off 
   the packet's tail, updates packet header accordingly. Returns 0 if OK, !0 otherwise.
*/
int tail_packet(unsigned char* pkt_buf, unsigned int pkt_buf_size, 
                unsigned short int fragment_offset, unsigned short int fragment_length);

/* ------------------------------------------------------------------------------------- */
/* Removes specified packets from tunnel queue, updates the tun_... variables accordingly. 
   Returns 0 if OK, !0 otherwise.
*/
int remove_queued_packets(unsigned int packet_index, unsigned int packet_count);

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer where VPN packet is being assembled, the size of that buffer,
   and information about packets being sent compressed. Appends one tailer per specified 
   packet, then seals and sends the packet. Returns 0 if OK, !0 otherwise.
*/
int send_compressed_packets(unsigned char* pkt_buf, unsigned int pkt_buf_size,
                            unsigned int packet_index, unsigned int packet_count);

/* ------------------------------------------------------------------------------------- */
/* Runs through the specified tunnelled packets, compresses them in a bunch, sends 
   compressed packets out. Returns -1 if failure, number of packets sent otherwise.
*/
int send_queued_packets(unsigned int packet_index, unsigned int packet_count);

/* ------------------------------------------------------------------------------------- */
/* Compresses and sends the specified packets, returns nothing. */

void flush_queued_packets(unsigned int packet_index, unsigned int packet_count);

/* ------------------------------------------------------------------------------------- */
/* zalloc and zfree are used with zlib calls, memory is allocated from a handful of static 
   buffers, to prevent dependency of dynamic memory allocator and avoid problems with signals.
   This relies on the fact that zlib only allocates a small (<= ZALLOC_COUNT)
   predictable set of buffers, each of which is sized <= ZALLOC_CHUNK. Also see zlib.h 
*/

voidpf zalloc(voidpf opaque, uInt items, uInt size);
void zfree(voidpf opaque, voidpf address);

/* ------------------------------------------------------------------------------------- */

#endif
