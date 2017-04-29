/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

/* Replay protection scheme:
   Each VPN packet is marked with the 64 bit sequence id of the form [x][y],
   where [x] is 32 bit epoch time on sender when the packet was sent, and [y] is
   a 32 bit packet counter also maintained and incremented by sender. Each
   received packet is either discarded or accepted. Each accepted packet's id
   is stored in the replay_window circular buffer in the appropriate position
   so that the buffer remains sorted.
   Replay protection uses two ideas:
   1. The incoming packet is discarded if its [x] is different from current
   time by more that replay_window_sec (specified in command line -y switch).
   This implies that clocks on Nest running peers must be kept loosely synchronized.
   2. The incoming packet is discarded if its id is present in the replay_window
   buffer OR it's less than the smallest of the id's in replay_window. This implies
   that packet delivery can't be delayed by more than it takes for REPLAY_WINDOW_SIZE
   newer packets to come in, otherwise its id will be considered inappropriately old.
*/

#include "nest.h"
#include "replay.h"
#include "debug_routines.h"

unsigned int replay_window_sec = DEFAULT_REPLAY_WINDOW_SEC;
unsigned long long replay_window[REPLAY_WINDOW_SIZE];
unsigned int replay_offset;

/* ------------------------------------------------------------------------------------- */

int check_replay(unsigned long long received_sequence_id, unsigned int pkt_time)
{

    unsigned int i, j;
    unsigned int packet_timestamp, time_difference;
    unsigned long long current_sequence_id;

    if (replay_window_sec > 0) /* check if the packet's timestamp is ok */
    {

        packet_timestamp = (unsigned int)(received_sequence_id >> 32);
        time_difference = (unsigned int)abs((long long)pkt_time - (long long)packet_timestamp); /* abs is necessary */

        if (time_difference > replay_window_sec) /* the packet is too old */
        {
#ifdef _DEBUG
            fprintf(debug, "Replay check says: packet is too old, timestamp difference = %.02d:%.02d:%.02d > %d second(s)\n",
                    time_difference / 3600, (time_difference % 3600) / 60, time_difference % 60, replay_window_sec);
#endif
            _syslog(LOG_WARNING, "Incoming packet is being discarded, timestamp difference = %.02d:%.02d:%.02d > %d second(s)",
                    time_difference / 3600, (time_difference % 3600) / 60, time_difference % 60, replay_window_sec);
            return 1;
        }

    }

    /* check if the packet's id is recorded in the replay bitmap */
    /* note that the replay bitmap is maintained sorted */

#ifdef _DEBUG
    dump_replay("Replay bitmap before check");
#endif

    current_sequence_id = replay_window[replay_offset];

    if (received_sequence_id > current_sequence_id) /* the new packet is newer than the newest we had so far */
    {
        replay_offset = (replay_offset + 1) % REPLAY_WINDOW_SIZE;
        replay_window[replay_offset] = received_sequence_id;
#ifdef _DEBUG
        fprintf(debug, "Replay check says: packet is perfectly fine\n");
        dump_replay("Replay bitmap after check");
#endif
        return 0;
    }

    if (received_sequence_id == current_sequence_id) /* the new packet is the current newest being replayed */
    {
#ifdef _DEBUG
        fprintf(debug, "Replay check says: the most recent packet is being replayed\n");
#endif
        return 1;
    }

    for (i = 1; i < REPLAY_WINDOW_SIZE; ++i) /* loop through all the recorded packets backwards */
    {

        current_sequence_id = replay_window[(replay_offset + REPLAY_WINDOW_SIZE - i) % REPLAY_WINDOW_SIZE];

        if (received_sequence_id > current_sequence_id) /* found the slot where the new packet fits */
        {

            for (j = 0; j < i; ++j) /* move all the newer packets one slot up to free this one */
            {
                replay_window[(replay_offset + REPLAY_WINDOW_SIZE - j + 1) % REPLAY_WINDOW_SIZE] =
                replay_window[(replay_offset + REPLAY_WINDOW_SIZE - j) % REPLAY_WINDOW_SIZE];
            }

            /* insert the new packet to the appropriate position */

            replay_window[(replay_offset + REPLAY_WINDOW_SIZE - i + 1) % REPLAY_WINDOW_SIZE] = received_sequence_id;
            replay_offset = (replay_offset + 1) % REPLAY_WINDOW_SIZE;

            break;

        }
        else if (received_sequence_id == current_sequence_id)
        {
#ifdef _DEBUG
            fprintf(debug, "Replay check says: packet is being replayed\n");
#endif
            return 1;
        }

    }

    if (received_sequence_id < current_sequence_id) /* all the packets in the bitmap are newer then the new one */
    {
#ifdef _DEBUG
        fprintf(debug, "Replay check says: packet is within time frame, but is older than the oldest recorded\n");
#endif
        return 1;
    }

#ifdef _DEBUG
    fprintf(debug, "Replay check says: packet came out of order, but is still valid\n");
    dump_replay("Replay bitmap after check");
#endif

    return 0;

}

/* ------------------------------------------------------------------------------------- */
