/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef interface_routines_h_included
#define interface_routines_h_included

#include "common_headers.h"

/* ------------------------------------------------------------------------------------- */

#define MAX_ICMP_RESPONSES 16

extern unsigned short int icmp_request_seq; /* when ICMP requests are used for sending, this would be the ICMP sequence id */

typedef struct /* this structure contains info about a single ICMP request received from the other side */
{
    unsigned short int id, seq;
    time_t expires;
}
icmp_response_t;

extern icmp_response_t icmp_responses[MAX_ICMP_RESPONSES];    /* when ICMP responses are used for sending */
extern int icmp_responses_count;                              /* this would be the buffer for recording requests */
extern int icmp_response_index;                               /* received from the other side */

/* ------------------------------------------------------------------------------------- */
/* These are the only routines interfaced to the outside world, they need
   to be most careful on their inputs and outputs.
*/

/* ------------------------------------------------------------------------------------- */
/* Takes handle to a tunnel, pointer to and size of a raw data buffer. Verifies that the
   packet indeed contains a valid IP packet, masquerades IP addresses on the packet if
   necessary, then sends it to the tunnel (injects inside the LAN). Returns size of the
   packet sent or -1.
*/

int write_tun(int d, unsigned char* buf, int nbytes);

/* ------------------------------------------------------------------------------------- */
/* Takes handle to a tunnel, pointer to and size of a raw data buffer. Reads raw IP packet
   from the tunnel, verifies its sanity and puts the whole IP packet to the provided buffer.
   Returns size of the IP packet or -1.
*/
int read_tun(int d, unsigned char* buf, int nbytes);

/* ------------------------------------------------------------------------------------- */
/* Takes handle to a socket, pointer to and size of a raw data buffer. Wraps the data
   into an IP (possibly ICMP too) packet as necessary to the current send settings and
   writes the IP packet to the socket. Returns amount of raw data sent or -1.
*/
int write_net(int d, unsigned char* buf, int nbytes);

/* ------------------------------------------------------------------------------------- */
/* Takes handle to a socket, pointer to and size of a raw data buffer. Reads raw IP packet
   from the socket, verifies its sanity, strips off IP header, (possibly ICMP header too)
   and puts the raw payload to the provided buffer. If this instance of Nest is receiving
   ICMP pings, ping information (seq, id, time) is recorded in the caller provided structure.
   Returns size of the payload or -1.
*/
int read_net(int d, unsigned char* buf, int nbytes, icmp_response_t* p_icmp_response);

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer and the size of the buffer, creates a fake valid IP packet
(not necessarily consisting of a header only). Returns size of the packet or -1.
*/
int fake_tun(unsigned char* buf, int nbytes);

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer with the packet and the size of the packet, returns 1 if
   the packet was created with fake_tun, 0 otherwise.
 */
int fake_packet(unsigned char* buf, int nbytes);

/* ------------------------------------------------------------------------------------- */
/* Removes pings that have been received too long ago. Returns number of available pings
   that still remain valid after the cleanup.
*/
int remove_expired_icmp_responses();

/* ------------------------------------------------------------------------------------- */
/* Registers the ICMP response fields passed in the pointed to structure in the
   icmp_responses cyclical buffer. Returns 0 if ok, !0 otherwise.
*/

int register_icmp_response(icmp_response_t* p_icmp_response);

/* ------------------------------------------------------------------------------------- */

#endif
