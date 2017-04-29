/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef crypto_h_included
#define crypto_h_included

#include "common_headers.h"
#include "blowfish.h"
#include "sha.h"

/* ------------------------------------------------------------------------------------- */

extern BF_KEY bf_key;              /* blowfish key schedule generated from h(enc_key) */
extern SHA_CTX auth_hash_context;  /* unfinalized h(auth_key|.) used for authenticating */
                                   /* outgoing VPN packets with HMAC of h(h(auth_key|M)) */
extern int keys_loaded;            /* boolean-like, 1 if current keys have been loaded */

extern BF_KEY new_bf_key;             /* the same pair of keys which are not yet in effect */
extern SHA_CTX new_auth_hash_context; /* pending for rotation after a recent HUP */

extern unsigned int switch_keys_at;   /* time when switch over to the new keys must occur */

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a complete (but unencrypted) valid VPN packet and current time.
   Finalizes fields contents, hmac authenticates and bf encrypts the packet. Returns the
   length of the resulting packet to send in bytes. Never fails, assuming the pointed to
   packet is valid.
*/
int seal_packet(struct vpn_header* pkt_head, unsigned int pkt_time);

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to an armoured VPN packet received from network, size of the packet and
   time when it was received. Bf decrypts and verifies hmac authentication.
   Returns 0 if packet is OK, !0 otherwise.
*/
int unseal_packet(unsigned char* pkt, unsigned int pkt_length, unsigned int pkt_time);

/* ------------------------------------------------------------------------------------- */

#endif
