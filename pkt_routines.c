/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#include "nest.h"
#include "pkt_routines.h"
#include "debug_routines.h"
#include "crypto.h"
#include "interface_routines.h"

/* ------------------------------------------------------------------------------------- */

int initialize_packet(unsigned char* pkt_buf, unsigned int pkt_buf_size)
{

    if (pkt_buf == 0 || pkt_buf_size < VPN_HEADER_SIZE) return 1;

    memset(pkt_buf, 0, VPN_HEADER_SIZE);
    return 0;

}

/* ------------------------------------------------------------------------------------- */

int tail_packet(unsigned char* pkt_buf, unsigned int pkt_buf_size,
                unsigned short int fragment_offset, unsigned short int fragment_length)
{

    struct vpn_header *pkt_head;
    struct vpn_tailer tailer;

    if (pkt_buf == 0 || pkt_buf_size < VPN_HEADER_SIZE || fragment_length == 0) return 1;

    pkt_head = (struct vpn_header *)pkt_buf;
    if (pkt_buf_size < PACKET_SIZE(pkt_head) + VPN_TAILER_SIZE) return 1;

    tailer.offset = htons(fragment_offset);
    tailer.length = htons(fragment_length);
    tailer.unused_zero = htonl(0);

    memmove(pkt_buf + PACKET_SIZE(pkt_head), &tailer, VPN_TAILER_SIZE);

    pkt_head->tailers_count += 1;

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int remove_queued_packets(unsigned int packet_index, unsigned int packet_count)
{

    unsigned int i;
    unsigned short int hole_offset, hole_size;

    if (packet_index + packet_count > tun_q_length || packet_count == 0) return 1;

    hole_offset = 0;
    hole_size = 0;

    for (i = 0; i < tun_q_length; ++i)
    {
        if (i < packet_index)
        {
            hole_offset += tun_q[i];
        }
        else if (i < packet_index + packet_count)
        {
            hole_size += tun_q[i];
            tun_q_bytes -= tun_q[i];
        }
        else
        {
            tun_q[i - packet_count] = tun_q[i];
        }
    }

    if (hole_size > 0 && tun_q_bytes > hole_offset)
    {
        memmove(tun_buf + hole_offset, tun_buf + hole_offset + hole_size, tun_q_bytes - hole_offset);
    }

    tun_q_length -= packet_count;

    if (tun_q_length == 0)
    {
        tun_q_timeout = 0;
    }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int zlib_compression_level;
unsigned char zalloc_buf[ZALLOC_CHUNK * ZALLOC_COUNT];
int zalloc_map[ZALLOC_COUNT];

voidpf zalloc(voidpf opaque, uInt items, uInt size)
{

    int i;

    if (items * size > ZALLOC_CHUNK)
    {
        _syslog(LOG_ERR, "zalloc() failed to allocate %d bytes, increase ZALLOC_CHUNK", items * size);
        return (voidpf)0;
    }

    for (i = 0; i < ZALLOC_COUNT; ++i)
    {
        if (zalloc_map[i] == 0)
        {
            zalloc_map[i] = 1;
            return (voidpf)(zalloc_buf + ZALLOC_CHUNK * i);
        }
    }

    _syslog(LOG_ERR, "zalloc() ran out of statically allocated buffers, increase ZALLOC_COUNT");
    return (voidpf)0;

}

void zfree(voidpf opaque, voidpf address)
{
    zalloc_map[((unsigned char*)address - zalloc_buf) / ZALLOC_CHUNK] = 0;
}

/* ------------------------------------------------------------------------------------- */

int send_compressed_packets(unsigned char* pkt_buf, unsigned int pkt_buf_size,
                            unsigned int packet_index, unsigned int packet_count)
{

    struct vpn_header *pkt_head;
    unsigned short int offset;
    unsigned int i;
    int wr;

    if (pkt_buf == 0 || pkt_buf_size < VPN_HEADER_SIZE || packet_count == 0 ||
        packet_index + packet_count > tun_q_length ||
        (send_mode == SEND_WITH_ECHO_RESPONSE && icmp_responses_count == 0)) return 1;

#ifdef _DEBUG
    fprintf(debug, "Sending compressed packets %d-%d\n", packet_index, packet_index + packet_count - 1);
#endif

    pkt_head = (struct vpn_header *)pkt_buf;

    /* append tailers to the assembled packet, one per contained packet */

    if (packet_count > 1) /* no need to add any tailers for a single packet */
    {
        offset = 0;
        for (i = packet_index; i < packet_index + packet_count; ++i)
        {
            if (tail_packet(pkt_buf, pkt_buf_size, offset, tun_q[i]) != 0) return 1;
            offset += tun_q[i];
        }
    }

    /* modify header flags if necessary */

    if (send_mode == SEND_WITH_ECHO_RESPONSE && icmp_responses_count == 1) /* this is the last packet we could send */
    {
        pkt_head->flags |= VHF_NEED_MORE_PINGS;
    }

    /* send the assembled packet */

    if ((wr = write_net(network, pkt_buf, seal_packet(pkt_head, time(0)))) == -1)
    {
        _syslog(LOG_WARNING, "write_net(%s) failed, %m", target_address);
        return 1;
    }

#ifdef _DEBUG
    fprintf(debug, "Written %d network bytes\n", wr);
#endif

    return 0;

}

/* ------------------------------------------------------------------------------------- */
/* This is a pretty complex routine which runs through a specified span of packets,
   attempts to compress as many of them as possible into a single network_mtu-sized packet,
   prefixed with a valid VPN header, fire that packet out and repeat until all packets
   are processed or no further sending is possible (ran out of ICMP responses using -e resp).
*/

int send_queued_packets(unsigned int packet_index, unsigned int packet_count)
{

    static unsigned char pkt_buf[BUFSIZE];
    struct vpn_header *pkt_head;
    unsigned char* pkt_payload;

    z_stream deflate_stream;

    unsigned short int compress_packet_offset;
    unsigned int first_compressed_packet_index;
    unsigned int compressed_packets_count;

    unsigned int i;

    if (packet_index + packet_count > tun_q_length || packet_count == 0 ||
        (send_mode == SEND_WITH_ECHO_RESPONSE && icmp_responses_count == 0)) return -1;

#ifdef _DEBUG
    fprintf(debug, "Sending packets %d-%d\n", packet_index, packet_index + packet_count - 1);
#endif

    /* set output buffer location and size */

    pkt_head = (struct vpn_header *)pkt_buf;
    pkt_payload = pkt_buf + VPN_HEADER_SIZE;

    /* prepare compression context */

    deflate_stream.zalloc = &zalloc;
    deflate_stream.zfree = &zfree;
    deflate_stream.opaque = 0;
    if (deflateInit(&deflate_stream, zlib_compression_level) != Z_OK) return -1;

    /* initialize scans and counters */

    first_compressed_packet_index = packet_index;
    compressed_packets_count = 0;

    /* find byte offset of the packet specified as first to send in the tun_buf */

    compress_packet_offset = 0;
    for (i = 0; i < packet_index; ++i) compress_packet_offset += tun_q[i];

    /* this loop ends when compressor walks through all the packets or if it uses up all ICMP responses */

    while (first_compressed_packet_index + compressed_packets_count < packet_index + packet_count)
    {

        if (compressed_packets_count == 0) /* (re)initialize compression state and VPN packet */
        {
            if ((first_compressed_packet_index > packet_index && deflateReset(&deflate_stream) != Z_OK) ||
                (initialize_packet(pkt_buf, sizeof(pkt_buf)) != 0))
            {
                deflateEnd(&deflate_stream);
                return -1;
            }
            deflate_stream.next_out = (Bytef*)pkt_payload;
            deflate_stream.avail_out = network_payload_size;
        }

        deflate_stream.next_in = (Bytef*)(tun_buf + compress_packet_offset); /* point to the packet to compress */
        deflate_stream.avail_in = (uLongf)tun_q[first_compressed_packet_index + compressed_packets_count];

        /* attempt to compress current packet appending it to the buffer */

#ifdef _DEBUG
        fprintf(debug, "Attempting to compress packet %d at queue offset %d, size %d, available output: %d\n",
                first_compressed_packet_index + compressed_packets_count, compress_packet_offset,
                deflate_stream.avail_in, deflate_stream.avail_out);
#endif

        /* the packet is successfully compressed if (1) deflate() call succeeds, */
        /* (2) all the input is processed and (3) there is enough bytes available in the buffer */
        /* for all the tailers that are to be appended (one per compressed packet, */
        /* single packet goes without a tailer) */

        if (deflate(&deflate_stream, Z_SYNC_FLUSH) == Z_OK && deflate_stream.avail_in == 0 &&
            deflate_stream.avail_out > (compressed_packets_count == 0 ? 0 : (compressed_packets_count + 1) * VPN_TAILER_SIZE))
        {
            compress_packet_offset += tun_q[first_compressed_packet_index + compressed_packets_count];
            compressed_packets_count += 1;
            pkt_head->data_length = network_payload_size - deflate_stream.avail_out; /* update packet data length */
            continue;
        }

#ifdef _DEBUG
        fprintf(debug, "Failed to compress packet, available input: %u, available output: %u, "
                "required for tailers: %u bytes\n", deflate_stream.avail_in, deflate_stream.avail_out,
                (unsigned int)(compressed_packets_count == 0 ? 0 : (compressed_packets_count + 1) * VPN_TAILER_SIZE));
#endif

        /* deflate failed, not enough space in the output buffer */

        if (compressed_packets_count > 0) /* send compressed packets to free up some buffer space and retry */
        {

            if (send_mode == SEND_WITH_ECHO_RESPONSE && icmp_responses_count == 1)
            {
#ifdef _DEBUG
                fprintf(debug, "Got one last ICMP response to send, breaking out of the compress/send loop\n");
#endif
                break;
            }

            if (send_compressed_packets(pkt_buf, sizeof(pkt_buf),
                                        first_compressed_packet_index, compressed_packets_count) != 0)
            {
                _syslog(LOG_WARNING, "send_compressed_packets() failed");
            }

            first_compressed_packet_index += compressed_packets_count;
            compressed_packets_count = 0;

        }
        else /* single packet is so huge that it won't fit under the payload even compressed, skip it */
        {
            _syslog(LOG_WARNING, "failed to squeeze a single packet under the specified MTU limit, the packet is lost");
            first_compressed_packet_index += 1;
        }

    } /* while not all packets are compressed/sent */

    if (compressed_packets_count > 0) /* send pending compressed packets */
    {
        if (send_compressed_packets(pkt_buf, sizeof(pkt_buf),
                                     first_compressed_packet_index, compressed_packets_count) != 0)
        {
            _syslog(LOG_WARNING, "send_compressed_packets() failed");
        }
    }

    /* this deflateEnd call actually terminates the stream prematurely, because we never call */
    /* deflate(..., Z_FINISH), but all the data we occassionally lose is the (checksum) zlib tailer */
    /* and we don't need it anyway */

    if (deflateEnd(&deflate_stream) != Z_DATA_ERROR) return -1;

    /* this may return less than the requested number of packets (packets_count) */
    /* if all the ICMP responses have been used and we broke out of the loop */

    return first_compressed_packet_index + compressed_packets_count - packet_index;

}

/* ------------------------------------------------------------------------------------- */

void flush_queued_packets(unsigned int packet_index, unsigned int packet_count)
{

    int packets_sent;

    /* if flush is requested, and ICMP response mode is used, at least one response is */
    /* available, see nest.c::tun_packet_switch::if check */

#ifdef _DEBUG
    fprintf(debug, "Flushing packets %d-%d\n", packet_index, packet_index + packet_count - 1);
#endif

    packets_sent = send_queued_packets(packet_index, packet_count);

    if (packets_sent <= 0) /* returns -1 on failure, should never return 0, just trying to be on the safe side */
    {
        _syslog(LOG_WARNING, "send_queued_packets() failed, the requested packets are forcefully removed from the queue");
        packets_sent = packet_count;
    }

    if (remove_queued_packets(packet_index, packets_sent) != 0)
    {
        _syslog(LOG_WARNING, "remove_queued_packets() failed");
    }

}

/* ------------------------------------------------------------------------------------- */
