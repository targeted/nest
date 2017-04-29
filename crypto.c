/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

/* seal/unseal: pair of functions to handle authentication/encryption of a VPN packet */

#include "nest.h"
#include "crypto.h"
#include "debug_routines.h"
#include "utilities.h"

/* ------------------------------------------------------------------------------------- */

BF_KEY bf_key;
SHA_CTX auth_hash_context;
int keys_loaded;

BF_KEY new_bf_key;
SHA_CTX new_auth_hash_context;
unsigned int switch_keys_at;

/* ------------------------------------------------------------------------------------- */

void switch_keys(
#ifdef _DEBUG
char* reason
#endif
)
{
#ifdef _DEBUG
    fprintf(debug, "The pending keys become current because %s\n", reason);
#endif
    memcpy(&bf_key, &new_bf_key, sizeof(BF_KEY));
    memset(&new_bf_key, 0, sizeof(BF_KEY));
    memcpy(&auth_hash_context, &new_auth_hash_context, sizeof(SHA_CTX));
    memset(&new_auth_hash_context, 0, sizeof(SHA_CTX));
    switch_keys_at = 0;
}

/* ------------------------------------------------------------------------------------- */

void switch_keys_if_time(unsigned int pkt_time)
{
    if (switch_keys_at > 0 && pkt_time > switch_keys_at)
    {
        switch_keys(
#ifdef _DEBUG
            "the current keys are no longer valid"
#endif
        );
    }
}

/* ------------------------------------------------------------------------------------- */

int seal_packet(struct vpn_header* pkt_head, unsigned int pkt_time)
{

    unsigned char enc_buf[BUFSIZE];
    unsigned int total_blocks;
    SHA_CTX data_hash_context;
    unsigned int data_hash[SHA_DIGEST_LENGTH / sizeof(unsigned int)];
    unsigned short int tail_bytes;
    BF_LONG ivec[2];

    static unsigned int last_pkt_time = 0;

    total_blocks = PACKET_SIZE_BLOCKS(pkt_head);

    /* wipe unused tail bytes */

    tail_bytes = XFER_ROUNDUP(pkt_head->data_length) - pkt_head->data_length;
    if (tail_bytes > 0)
    {
        memset((unsigned char*)pkt_head + VPN_HEADER_SIZE + pkt_head->data_length, 0, tail_bytes);
    }

    /* register sequence number of the packet */

    if (pkt_time > last_pkt_time) /* reset the counter to keep sequence more random yet monotonical */
    {
        sequence_id = ((unsigned)random()) % 0xff000000; /* this is now in range 0 to 0xfeffffff which is still */
    }                                                    /* enough for 16M packets/next second in the worst case */
    last_pkt_time = pkt_time;

    pkt_head->sequence_id = htonull((((unsigned long long)last_pkt_time) << 32) | sequence_id);
    sequence_id += 1;

    /* as a final touch to the header, convert the rest of header fields to network format */

    pkt_head->data_length = htons(pkt_head->data_length);

    /* note that when sending we always use the "current" pair of keys, but a switch may be due */

    switch_keys_if_time(pkt_time);

    /* but if the new keys are still not being used */

    if (switch_keys_at > 0) /* then hint the peer that we have a new set of keys pending */
    {
        pkt_head->flags |= VHF_SWITCHING_KEYS;
    }

    /* calculate h(auth_key|m) using precalculated unfinalized h(auth_key) */

    memmove(&data_hash_context, &auth_hash_context, sizeof(SHA_CTX));
    SHA1_Update(&data_hash_context, (unsigned char*)pkt_head + 3 * sizeof(unsigned int),
                total_blocks * XFER_BLOCKSIZE - 3 * sizeof(unsigned int));
    SHA1_Final((unsigned char*)data_hash, &data_hash_context);

#ifdef _DEBUG
    dump_data("h(auth_key|m)", (unsigned char*)data_hash, sizeof(data_hash));
#endif

    /* data_hash contains h(auth_key|m) */

    SHA1_Init(&data_hash_context);
    SHA1_Update(&data_hash_context, (unsigned char*)data_hash, sizeof(data_hash));
    SHA1_Final((unsigned char*)data_hash, &data_hash_context);

#ifdef _DEBUG
    dump_data("h(h(auth_key|m))", (unsigned char*)data_hash, sizeof(data_hash));
#endif

    /* data_hash contains h(h(auth_key|m)), downsample 160 bit to 96 bits and store in the header */

    pkt_head->data_hash[0] = htonl(data_hash[0] ^ data_hash[1]);
    pkt_head->data_hash[1] = htonl(data_hash[1] ^ data_hash[2] ^ data_hash[3]);
    pkt_head->data_hash[2] = htonl(data_hash[3] ^ data_hash[4]);

    /* apply strong encryption, paint over with blowfish */

    /* first block of the data being encrypted contains the hash and the hashed data in turn contained */
    /* sequence id so the first block makes a reasonable ivec all by itself */

    ivec[0] = ivec[1] = 0;

#ifdef _DEBUG
    dump_data("Packet before encryption", (unsigned char*)pkt_head, total_blocks * XFER_BLOCKSIZE);
#endif
    BF_cbc_encrypt((unsigned char*)pkt_head, enc_buf, total_blocks * XFER_BLOCKSIZE, &bf_key, (unsigned char*)&(ivec[0]), BF_ENCRYPT);
    memmove((unsigned char*)pkt_head, enc_buf, total_blocks * XFER_BLOCKSIZE);
#ifdef _DEBUG
    dump_data("Packet after encryption", (unsigned char*)pkt_head, total_blocks * XFER_BLOCKSIZE);
#endif

    return total_blocks * XFER_BLOCKSIZE;

}

/* ------------------------------------------------------------------------------------- */

int decrypt_verify_packet(unsigned char* pkt, unsigned int pkt_length, unsigned int pkt_time,
                          BF_KEY* p_bf_key, SHA_CTX* p_auth_hash_context)
{

    unsigned int total_blocks;
    struct vpn_header *pkt_head;
    SHA_CTX data_hash_context;
    unsigned int data_hash[SHA_DIGEST_LENGTH / sizeof(unsigned int)];
    BF_LONG ivec[2];
    unsigned char dec_buf[BUFSIZE];

    /* initial sanity checks */

    if (pkt == 0 || pkt_length % XFER_BLOCKSIZE != 0) return 1;
    total_blocks = pkt_length / XFER_BLOCKSIZE;
    if (total_blocks < VPN_HEADER_BLOCKS) return 1;

    pkt_head = (struct vpn_header *)pkt;

    /* remove strong encryption layer */

    ivec[0] = ivec[1] = 0;

#ifdef _DEBUG
    dump_data("Packet before decryption", pkt, total_blocks * XFER_BLOCKSIZE);
#endif
    BF_cbc_encrypt(pkt, dec_buf, total_blocks * XFER_BLOCKSIZE, p_bf_key, (unsigned char*)&(ivec[0]), BF_DECRYPT);
    memmove(pkt, dec_buf, total_blocks * XFER_BLOCKSIZE);
#ifdef _DEBUG
    dump_data("Packet after decryption", pkt, total_blocks * XFER_BLOCKSIZE);
#endif

    /* verify packet checksum */

    memmove(&data_hash_context, p_auth_hash_context, sizeof(SHA_CTX));
    SHA1_Update(&data_hash_context, pkt + 3 * sizeof(unsigned int),
                total_blocks * XFER_BLOCKSIZE - 3 * sizeof(unsigned int));
    SHA1_Final((unsigned char*)data_hash, &data_hash_context);

    /* data_hash contains h(auth_key|m) */

    SHA1_Init(&data_hash_context);
    SHA1_Update(&data_hash_context, (unsigned char*)data_hash, sizeof(data_hash));
    SHA1_Final((unsigned char*)data_hash, &data_hash_context);

    /* data_hash contains h(h(auth_key|m)), check it against the value stored in the header */

    if ((pkt_head->data_hash[0] != htonl(data_hash[0] ^ data_hash[1])) ||
        (pkt_head->data_hash[1] != htonl(data_hash[1] ^ data_hash[2] ^ data_hash[3])) ||
        (pkt_head->data_hash[2] != htonl(data_hash[3] ^ data_hash[4])))
    {
#ifdef _DEBUG
    fprintf(debug, "Packet checksum mismatch\n");
#endif
        return 1;
    }

    /* checksum check passed, it's VERY likely to be a valid packet */

    /* convert data fields back from network to host format */

    pkt_head->data_length = ntohs(pkt_head->data_length);
    pkt_head->sequence_id = ntohull(pkt_head->sequence_id);

    if (PACKET_SIZE_BLOCKS(pkt_head) != total_blocks) return 1;

#ifdef _DEBUG
    fprintf(debug, "Packet checksum correct\n");
#endif

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int unseal_packet(unsigned char* pkt, unsigned int pkt_length, unsigned int pkt_time)
{

    static unsigned char pkt_copy[BUFSIZE];

    int res;
    struct vpn_header *pkt_head;

    /* when receiving we will accept both the current and the new keys */
    /* and also now there are three possible reasons for key switch */

    switch_keys_if_time(pkt_time); /* first reason to switch: due time */

    if (switch_keys_at > 0) /* two sets of keys are temporarily in effect */
    {
#ifdef _DEBUG
        fprintf(debug, "Trying the pending keys to decrypt and verify the packet\n");
#endif
        memcpy(pkt_copy, pkt, pkt_length); /* decryption is done in place therefore we need to copy it */
        if (decrypt_verify_packet(pkt_copy, pkt_length, pkt_time, &new_bf_key, &new_auth_hash_context) == 0)
        {
            memcpy(pkt, pkt_copy, pkt_length); /* and after successful decryption copy it back */
            switch_keys(
#ifdef _DEBUG
                "the peer uses them already" /* second reason to switch */
#endif
            );
            return 0;
        }
#ifdef _DEBUG
        fprintf(debug, "Didn't work, proceeding with the current keys as usual\n");
#endif
    }

    /* otherwise try the current set of keys as usual */

    res = decrypt_verify_packet(pkt, pkt_length, pkt_time, &bf_key, &auth_hash_context);
    if (res != 0) return res;

    if (switch_keys_at > 0) /* we are ready to switch, let's see if the peer is too */
    {
        pkt_head = (struct vpn_header *)(pkt);
        if ((pkt_head->flags & VHF_SWITCHING_KEYS) != 0)
        {
            /* this switch is opportunistic, hoping that both sides have the same new keys */
            switch_keys(
#ifdef _DEBUG
                "the peer hints of having new keys" /* third reason to switch */
#endif
            );
        }
    }

    return 0;

}

/* ------------------------------------------------------------------------------------- */
