/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef debug_routines_h_included
#define debug_routines_h_included

#ifdef _DEBUG

#include "common_headers.h"

extern FILE* debug;

void dump_data(char* message, unsigned char* data, unsigned int data_length);
void dump_queue(char* message);
void dump_replay(char* message);
void dump_icmp_responses(char* message);

#endif

#endif
