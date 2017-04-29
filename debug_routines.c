/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifdef _DEBUG

#include "nest.h"
#include "debug_routines.h"
#include "replay.h"
#include "interface_routines.h"

/* ------------------------------------------------------------------------------------- */

FILE* debug;

/* ------------------------------------------------------------------------------------- */

void dump_data(char* message, unsigned char* data, unsigned int data_length)
{
    unsigned int i;
    fprintf(debug, "%s (%d/0x%x):\n", message, data_length, data_length);
    for (i = 0; i < data_length; ++i)
    {
        if (i == data_length - 1)
        {
            fprintf(debug, "%.02x", data[i]);
        }
        else
        {
            fprintf(debug, "%.02x:", data[i]);
        }
    }
    fprintf(debug, "\n");
}

/* ------------------------------------------------------------------------------------- */

void dump_queue(char* message)
{
    unsigned int i, j, offset;
    fprintf(debug, "%s, packet queue: %d packets, %d bytes:\n", message, tun_q_length, tun_q_bytes);
    for (i = 0, offset = 0; i < tun_q_length; ++i)
    {
        fprintf(debug, "%.02d (%.05d/0x%.04x): ", i, tun_q[i], tun_q[i]);
        for (j = 0; j < tun_q[i]; ++j)
        {
            if (j == tun_q[i] - 1)
            {
                fprintf(debug, "%.02x", (tun_buf + offset)[j]);
            }
            else
            {
                fprintf(debug, "%.02x:", (tun_buf + offset)[j]);
            }
        }
        offset += tun_q[i];
        fprintf(debug, "\n");
    }
}

/* ------------------------------------------------------------------------------------- */

void dump_replay(char* message)
{
    unsigned int i;
    fprintf(debug, "%s, replay map contents:\n", message);
    for (i = 0; i < REPLAY_WINDOW_SIZE; ++i)
    {
        fprintf(debug, "%.016llx ", replay_window[(replay_offset + REPLAY_WINDOW_SIZE - i) % REPLAY_WINDOW_SIZE]);
    }
    fprintf(debug, "\n");
}

/* ------------------------------------------------------------------------- */

void dump_icmp_responses(char* message)
{
    int i;
    fprintf(debug, "%s, available ICMP responses: ", message);
    for (i = 0; i < icmp_responses_count; ++i)
    {
        fprintf(debug, "(%d, seq = 0x%04x, id = 0x%04x) ", i,
                icmp_responses[(icmp_response_index + i) % MAX_ICMP_RESPONSES].seq,
                icmp_responses[(icmp_response_index + i) % MAX_ICMP_RESPONSES].id);
    }
    fprintf(debug, "\n");
}

/* ------------------------------------------------------------------------- */

#endif
