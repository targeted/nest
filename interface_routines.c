/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#include "nest.h"
#include "interface_routines.h"
#include "debug_routines.h"
#include "utilities.h"

/* ------------------------------------------------------------------------------------- */

unsigned short int icmp_request_seq;

icmp_response_t icmp_responses[MAX_ICMP_RESPONSES];
int icmp_responses_count;
int icmp_response_index;

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a buffer with an IP packet (presumably) and the size of the packet.
   Verifies packet validity, fixes any problems it can, returns -1 if the packet is invalid,
   otherwise returns the correct packet size (may be less than the original size).
*/
int validate_ip_packet(unsigned char* buf, int nbytes)
{

    int ip_header_length;
    struct ip* p_ip;

    return nbytes;

    if (buf == 0 || nbytes < sizeof(struct ip)) return -1; /* the packet has to be at least as large as the minimal IP header */

    p_ip = (struct ip*)buf;
    if (p_ip->ip_v != 4) return -1;

    ip_header_length = p_ip->ip_hl << 2;
    if (nbytes < ip_header_length) return -1;

    /* fix the length problem if necessary with the strange packet reads on raw socket */

    if (nbytes < ntohs(p_ip->ip_len)) p_ip->ip_len = htons(nbytes);

    /* calculate and overwrite IP header checksum, we could compare it, but comparing */
    /* requires calculating anyway, and it's not clear what to do with the packets with */
    /* broken checksums, as they do come from the raw socket */

    p_ip->ip_sum = 0;
    p_ip->ip_sum = ip_checksum((unsigned char*)p_ip, ip_header_length, 0);

    return ntohs(p_ip->ip_len); /* this may return less than nbytes */

}


/* ------------------------------------------------------------------------------------- */
/* this structure encapsulates the imaginary pseudo IP header, included in checksum
   calculation with TCP and UDP protocols
*/

typedef struct
{
    u_int32_t src;
    u_int32_t dst;
    u_char zero;
    u_char protocol;
    u_int16_t length;
}
ippseudohdr_t;

/* ------------------------------------------------------------------------------------- */
/* Takes pointer to a valid IP packet and the size of the packet. Changes source and/or
   destination IP addresses in the IP packet header, corrects IP checksum, then corrects
   checksums for TCP, UDP protocols. Packets of any other protocol go unchanged, quite
   possibly broken. Returns 0 if ok, -1 otherwise.
*/
int masquerade_known_protocols(struct ip* p_ip, int ip_packet_length)
{

    /* no IP validity checks, assuming masquerade_known_protocols is only called from within */
    /* write_tun, after the call to validate_ip_packet */

    int ip_header_length = p_ip->ip_hl << 2;

    struct tcphdr* p_tcp;
    unsigned int tcp_packet_length;
    struct udphdr* p_udp;
    unsigned int udp_packet_length;
    ippseudohdr_t ippseudohdr;
    unsigned int running_checksum;

    /* patch IP header */

    if (tunnel_masquerade_source == 1)
    {
        p_ip->ip_src.s_addr = tunnel_masquerade_source_sockinfo.sin_addr.s_addr;
    }

    if (tunnel_masquerade_destination == 1)
    {
        p_ip->ip_dst.s_addr = tunnel_masquerade_destination_sockinfo.sin_addr.s_addr;
    }

    ippseudohdr.src = p_ip->ip_src.s_addr;
    ippseudohdr.dst = p_ip->ip_dst.s_addr;
    ippseudohdr.zero = 0;

    /* fix checksums for known protocols, starting with obvious IP header checksum */

    p_ip->ip_sum = 0;
    p_ip->ip_sum = ip_checksum((unsigned char*)p_ip, ip_header_length, 0);

    switch (p_ip->ip_p)
    {

    case IPPROTO_TCP:

        if (ip_packet_length < ip_header_length + sizeof(struct tcphdr)) return -1;

        p_tcp = (struct tcphdr*)((unsigned char*)p_ip + ip_header_length);
        tcp_packet_length = ip_packet_length - ip_header_length;

        ippseudohdr.length = htons(tcp_packet_length & 0xffff);
        ippseudohdr.protocol = IPPROTO_TCP;

        running_checksum = 0;
        ip_checksum((unsigned char*)&ippseudohdr, sizeof(ippseudohdr), &running_checksum);
        p_tcp->th_sum = 0;
        p_tcp->th_sum = ip_checksum((unsigned char*)p_tcp, tcp_packet_length, &running_checksum);

        break;

    case IPPROTO_UDP:

        if (ip_packet_length < ip_header_length + sizeof(struct udphdr)) return -1;

        p_udp = (struct udphdr*)((unsigned char*)p_ip + ip_header_length);
        udp_packet_length = ip_packet_length - ip_header_length;

        ippseudohdr.length = htons(udp_packet_length & 0xffff);
        ippseudohdr.protocol = IPPROTO_UDP;

        running_checksum = 0;
        ip_checksum((unsigned char*)&ippseudohdr, sizeof(ippseudohdr), &running_checksum);
        p_udp->uh_sum = 0;
        p_udp->uh_sum = ip_checksum((unsigned char*)p_udp, udp_packet_length, &running_checksum);

        break;

    default:

        break;

    }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int write_tun(int d, unsigned char* buf, int nbytes)
{

    int ip_packet_length = validate_ip_packet(buf, nbytes);
    if (ip_packet_length != nbytes) return -1;

    /* the above check helps to ensure we only inject a valid IP packet into the LAN */

    /* patch IP packet if necessary */

    if (tunnel_masquerade_source == 1 || tunnel_masquerade_destination == 1)
    {
        if (masquerade_known_protocols((struct ip*)buf, ip_packet_length) == -1) return -1;
    }

#ifdef _DEBUG
    dump_data("Sending IP packet to the tunnel", buf, ip_packet_length);
#endif

    return write(d, buf, ip_packet_length) == ip_packet_length ? ip_packet_length : -1;

}

/* ------------------------------------------------------------------------------------- */

int read_tun(int d, unsigned char* buf, int nbytes)
{

    int result;

#ifdef _DEBUG
    fprintf(debug, "Reading %d bytes from the tunnel\n", nbytes);
#endif

    /* perform physical read to the buffer */

    if ((result = read(d, buf, nbytes)) <= 0) return -1;

    /* assuming IP packet is read, perform basic checks on it */

#ifdef _DEBUG
    dump_data("Received plain packet", buf, result);
#endif

    return validate_ip_packet(buf, result); /* returns -1 or correct packet size */

}

/* ------------------------------------------------------------------------------------- */

int fake_tun(unsigned char* buf, int nbytes)
{

    struct ip* p_ip;

    if (buf == 0 || nbytes < sizeof(struct ip)) return -1;

    p_ip = (struct ip*)buf;
    p_ip->ip_v = 4;
    p_ip->ip_hl = sizeof(struct ip) >> 2;
    p_ip->ip_tos = 0;
    p_ip->ip_len = htons(sizeof(struct ip));
    p_ip->ip_id = random() & 0xffff;
    p_ip->ip_off = 0;
    p_ip->ip_ttl = 64;
    p_ip->ip_p = 0;
    p_ip->ip_src.s_addr = 0;
    p_ip->ip_dst.s_addr = 0;
    p_ip->ip_sum = 0;
    p_ip->ip_sum = ip_checksum((unsigned char*)p_ip, sizeof(struct ip), 0);

    return sizeof(struct ip);

}

/* ------------------------------------------------------------------------------------- */

int fake_packet(unsigned char* buf, int nbytes)
{

    struct ip* p_ip;
    if (buf == 0 || nbytes != sizeof(struct ip)) return 0;

    p_ip = (struct ip*)buf;

    if (p_ip->ip_p == 0 && p_ip->ip_len == htons(sizeof(struct ip)) &&
        p_ip->ip_src.s_addr == 0 && p_ip->ip_dst.s_addr == 0) return 1;

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int write_net(int d, unsigned char* buf, int nbytes)
{

    int send_bytes;
    unsigned char send_buf[BUFSIZE];
    struct icmp* p_icmp;
    struct ip* p_ip;
    unsigned char* p_data;

    /* for everything else but ICMP just send */

    if (protocol != IPPROTO_ICMP)
    {
#ifdef _DEBUG
        dump_data("Sending raw packet to the network", buf, nbytes);
#endif
        return send(d, buf, nbytes, 0) == nbytes ? nbytes : -1;
    }

    /* with ICMP the behaviour differs for requests and responses */
    /* requests go through a connected raw socket and only need to be wrapped in an ICMP packet */
    /* responses go through an unconnected divert socket and need to be wrapped in an IP packet as well */

    /* the packet will be assembled in send_buf, also pointed to by p_ip, p_icmp and p_data */

    if (send_mode == SEND_WITH_ECHO_RESPONSE) /* sending through an unconnected divert socket */
    {
        p_ip = (struct ip*)send_buf;
        p_icmp = (struct icmp*)(send_buf + sizeof(struct ip)); /* sizeof(struct ip) is fine, we are going to assemble our own packet */
        p_data = (unsigned char*)p_icmp + SIZEOF_ICMP;
        send_bytes = nbytes + sizeof(struct ip) + SIZEOF_ICMP;
    }
    else /* sending through a connected divert socket */
    {
        p_ip = 0;
        p_icmp = (struct icmp*)send_buf;
        p_data = (unsigned char*)p_icmp + SIZEOF_ICMP;
        send_bytes = nbytes + SIZEOF_ICMP;
    }

    if (send_bytes > AVAIL_BUFSIZE) return -1;

    /* copy raw data to the payload */

    memmove(p_data, buf, nbytes);

    /* creating a proper ICMP request/response packet header */

    if (send_mode == SEND_WITH_ECHO_REQUEST) /* can always send a new request */
    {
        p_icmp->icmp_type = ICMP_ECHO;
        p_icmp->icmp_code = 0;
        p_icmp->icmp_cksum = 0;
        p_icmp->icmp_id = pid & 0xffff;
        p_icmp->icmp_seq = icmp_request_seq;
        icmp_request_seq += 1;
    }
    else if (send_mode == SEND_WITH_ECHO_RESPONSE) /* but require an existing response */
    {
        if (icmp_responses_count == 0) return -1; /* this shouldn't normally happen, just a safety measure */
        p_icmp->icmp_type = ICMP_ECHOREPLY;
        p_icmp->icmp_code = 0;
        p_icmp->icmp_cksum = 0;
        p_icmp->icmp_id = icmp_responses[icmp_response_index].id;
        p_icmp->icmp_seq = icmp_responses[icmp_response_index].seq;
        icmp_response_index = (icmp_response_index + 1) % MAX_ICMP_RESPONSES;
        icmp_responses_count -= 1;
#ifdef _DEBUG
        dump_icmp_responses("Used up a PONG");
#endif
    }

    p_icmp->icmp_cksum = ip_checksum((unsigned char*)p_icmp, nbytes + SIZEOF_ICMP, 0);

    /* this completes the creation of an ICMP packet */

    if (p_ip != 0) /* need to create a proper IP packet header as well */
    {

        p_ip->ip_v = 4;
        p_ip->ip_hl = sizeof(struct ip) >> 2;
        p_ip->ip_tos = 0;
        p_ip->ip_len = htons(send_bytes);
        p_ip->ip_id = random() & 0xffff;
        p_ip->ip_off = 0;
        p_ip->ip_ttl = 64;
        p_ip->ip_p = IPPROTO_ICMP;
        p_ip->ip_src.s_addr = source_sockinfo.sin_addr.s_addr;
        p_ip->ip_dst.s_addr = target_sockinfo.sin_addr.s_addr;
        p_ip->ip_sum = 0;
        p_ip->ip_sum = ip_checksum((unsigned char*)p_ip, sizeof(struct ip), 0);

        /* this completes the creation of an IP packet */

    }


#ifdef _DEBUG
    if (p_ip != 0)
    {
        dump_data("Sending IP packet to the network", send_buf, send_bytes);
    }
    else
    {
        dump_data("Sending ICMP packet to the network", send_buf, send_bytes);
    }
#endif

    /* ip_divert.c:
           RELENG_5 revision 1.98.2.1 and RELENG_4 revision 1.42.2.7:
       Since divert protocol is not connection oriented, remove SS_ISCONNECTED flag from divert sockets.
       Therefore send() can no longer be used with divert sockets.
    */

    if (send_mode == SEND_WITH_ECHO_RESPONSE) /* sending through an unconnected divert socket */
    {
        return sendto(d, send_buf, send_bytes, 0, (struct sockaddr*)&blank_sockinfo, sizeof(struct sockaddr_in)) == send_bytes ? send_bytes : -1;
    }
    else /* sending through a connected raw socket */
    {
        return send(d, send_buf, send_bytes, 0) == send_bytes ? send_bytes : -1;
    }

}

/* ------------------------------------------------------------------------------------- */

int read_net(int d, unsigned char* buf, int nbytes, icmp_response_t* p_icmp_response)
{

    int result;
    unsigned char recv_buf[BUFSIZE];
    struct ip* p_ip;
    struct icmp* p_icmp;
    unsigned short original_icmp_checksum;
    int ip_packet_size, ip_header_length, icmp_packet_size;

    if (buf == 0 || nbytes <= 0 || nbytes > AVAIL_BUFSIZE ||
        (send_mode == SEND_WITH_ECHO_RESPONSE && p_icmp_response == 0) ||
        (send_mode != SEND_WITH_ECHO_RESPONSE && p_icmp_response != 0)) return -1;

    /* both raw and divert sockets deliver a raw IP packet */

    ip_packet_size = recv(d, recv_buf, nbytes, 0); /* therefore ip_packet_size <= nbytes */
    if (ip_packet_size == -1) return -1;

#ifdef _DEBUG
    dump_data("Received raw packet", recv_buf, ip_packet_size);
#endif

    /* verify packet's sanity */

    ip_packet_size = validate_ip_packet(recv_buf, ip_packet_size);
    if (ip_packet_size == -1) return -1;

#ifdef _DEBUG
    dump_data("Received IP packet", recv_buf, ip_packet_size);
#endif

    p_ip = (struct ip*)recv_buf;
    ip_header_length = p_ip->ip_hl << 2;

    /* check the protocol and the sender of the packet, just in case */

    if (p_ip->ip_p != protocol || p_ip->ip_src.s_addr != target_sockinfo.sin_addr.s_addr) return -1;

    /* for everything else but ICMP, just strip off the IP header */

    if (protocol != IPPROTO_ICMP)
    {
        result = ip_packet_size - ip_header_length;
        memmove(buf, ((char*)p_ip) + ip_header_length, result);
        return result;
    }

    /* handle a received ICMP packet */

    if (ip_packet_size <= ip_header_length + SIZEOF_ICMP) return -1; /* not an icmp packet */

    p_icmp = (struct icmp*)(recv_buf + ip_header_length);
    icmp_packet_size = ip_packet_size - ip_header_length;

    if (p_icmp->icmp_type != (send_mode == SEND_WITH_ECHO_RESPONSE ? ICMP_ECHO : ICMP_ECHOREPLY) ||
        p_icmp->icmp_code != 0) return -1; /* unexpected type of icmp packet */

#ifdef _DEBUG
    dump_data("Received ICMP packet", (unsigned char*)p_icmp, icmp_packet_size);
#endif

    /* verify icmp checksum */

    original_icmp_checksum = p_icmp->icmp_cksum;
    p_icmp->icmp_cksum = 0;
    if (ip_checksum((unsigned char*)p_icmp, icmp_packet_size, 0) != original_icmp_checksum) return -1;

    /* ICMP checksum is valid */

    if (send_mode == SEND_WITH_ECHO_RESPONSE && p_icmp_response != 0) /* return echo request information for the caller to register later */
    {
        p_icmp_response->id = p_icmp->icmp_id;
        p_icmp_response->seq = p_icmp->icmp_seq;
        p_icmp_response->expires = time(0) + PING_LIFETIME_SEC;
    }

    result = icmp_packet_size - SIZEOF_ICMP;
    memmove(buf, ((char*)p_icmp) + SIZEOF_ICMP, result);

    return result;

}

/* ------------------------------------------------------------------------------------- */

int remove_expired_icmp_responses()
{

    time_t time_now;

#ifdef _DEBUG
    dump_icmp_responses("Available pings before timeout cleanup");
#endif

    if (icmp_responses_count > 0)
    {
        time_now = time(0);
        while (icmp_responses_count > 0)
        {
            if (time_now > icmp_responses[icmp_response_index].expires)
            {
                icmp_response_index = (icmp_response_index + 1) % MAX_ICMP_RESPONSES;
                icmp_responses_count -= 1;
            }
            else
            {
                break; /* the pings are registered in FIFO order */
            }
        }
    }

#ifdef _DEBUG
    dump_icmp_responses("Available pings after timeout cleanup");
#endif

    return icmp_responses_count;

}

/* ------------------------------------------------------------------------------------- */

int register_icmp_response(icmp_response_t* p_icmp_response)
{

    int icmp_response_store_index;

    if (p_icmp_response == 0) return 1;

    if (icmp_responses_count < MAX_ICMP_RESPONSES) /* append the response at the end of the buffer */
    {
        icmp_response_store_index = (icmp_response_index + icmp_responses_count) % MAX_ICMP_RESPONSES;
        icmp_responses[icmp_response_store_index].id = p_icmp_response->id;
        icmp_responses[icmp_response_store_index].seq = p_icmp_response->seq;
        icmp_responses[icmp_response_store_index].expires = p_icmp_response->expires;
        icmp_responses_count += 1;
    }
    else /* overwrite the oldest response */
    {
        icmp_responses[icmp_response_index].id = p_icmp_response->id;
        icmp_responses[icmp_response_index].seq = p_icmp_response->seq;
        icmp_responses[icmp_response_index].expires = p_icmp_response->expires;
        icmp_response_index = (icmp_response_index + 1) % MAX_ICMP_RESPONSES;
    }

#ifdef _DEBUG
    dump_icmp_responses("Registered a PING");
#endif

    return 0;

}

/* ------------------------------------------------------------------------------------- */
