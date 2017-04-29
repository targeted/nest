/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef replay_h_included
#define replay_h_included

#include "common_headers.h"

#define REPLAY_WINDOW_SIZE 64        /* number of packets to keep track for (this basically accounts for the worst case of the out of order IP packets arrival) */
#define DEFAULT_REPLAY_WINDOW_SEC 60 /* default time frame for replay protection is one minute, which sounds reasonable */
#define MAX_REPLAY_WINDOW_SEC 3600   /* one must definetely know what replay is before setting the window size even that high */

extern unsigned long long replay_window[REPLAY_WINDOW_SIZE];  /* circular buffer with received packet id's */
extern unsigned int replay_offset;                            /* index of the head of the buffer */
extern unsigned int replay_window_sec;                        /* clocks on Nest running peers must be kept synchronized within this value */

/* ------------------------------------------------------------------------------------- */
/* Takes 64 bit packet id of the form [32 bit time][32 bit counter] and time when the
   packet was received, checks whether packet time is within the replay window size
   specified with -y command line parameter, consults packet validity with the replay
   bitmap that contains id already received, then modifies the replay bitmap appropriately.
   Returns 0 if the packet is fine, !0 if it's to be discarded.
*/

int check_replay(unsigned long long received_sequence_id, unsigned int pkt_time);

/* ------------------------------------------------------------------------------------- */

#endif
