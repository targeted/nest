/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

#ifndef nest_h_included
#define nest_h_included

#include "common_headers.h"

/* ------------------------------------------------------------------------------------- */

#define MAX_QUEUED_PACKETS 16                   /* max. number of LAN packets to queue before flush sending */

#define BUFSIZE 0x10000                         /* size of all the network packet buffers, don't touch */
#define AVAIL_BUFSIZE 0xffff                    /* exactly one less than BUFSIZE, must also fit into an unsigned int */

#define Q_DELAY_MS 100                          /* default delay in ms to keep the queue before flush sending */
#define Q_DELAY_MS_MAX 1000                     /* max -//- */
#define Q_DELAY_MS_MIN MAX_QUEUED_PACKETS       /* min -//- */

#define PING_LIFETIME_SEC 3                     /* with ICMP response mode, the incoming pings will expire after that number of seconds */

#define PROTO 99                                /* default ip protocol (ipip) for VPN packets */
#define PID_FILENAME "/var/run/nest.pid"        /* default pid file name */

#define NO_STD_CLOSE 1
#define NO_CHROOT 1

#define PKT_DROP       0                        /* constants returned from tun_packet_switch() */
#define PKT_SEND       1
#define PKT_SEND_OOB   2
#define PKT_DELAY      3

#define SEND_NORMAL 0                           /* protocol other than ICMP is used */
#define SEND_WITH_ECHO_REQUEST 1                /* ICMP is used, sending only echo requests */
#define SEND_WITH_ECHO_RESPONSE 2               /* ICMP is used, sending only echo responses */

#define DEFAULT_NETWORK_MTU 1500

#define SMALL_PACKET_THRESHOLD 8                /* TCP & UDP packets of this size and less will cause the queue to be flushed */

#define XFER_BLOCKSIZE (BF_BLOCK)               /* assuming blowfish is used, these macros do all sorts of block size round ups */
#define XFER_BLOCKS(X) (((X) + XFER_BLOCKSIZE - 1) / XFER_BLOCKSIZE)
#define XFER_ROUNDUP(X) (XFER_BLOCKS(X) * XFER_BLOCKSIZE)

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#define SIZEOF_ICMP ICMP_MINLEN

#ifdef NO_SYSLOG
#define LOG_ERR 0xCCCCCCCC
#define LOG_WARNING 0xCCCCCCCC
void _syslog(int priority, const char *message, ...);
#else
#define _syslog syslog
#endif

#define errmsg(X) { if (write_to_syslog == 0) fprintf(stderr, "%s\n", X); else _syslog(LOG_ERR, "%s\n", X); }
#define err(X) { if (errno != 0) { snprintf(err_buf, LINE_MAX, "%s: %s.", X, strerror(errno)); errmsg(err_buf); errno = 0; } }
#define TRY(X) { int res; if ((res = (X)) != 0) { err("TRY()"); if (res >= 0) return res; else return -res; } }

/* ------------------------------------------------------------------------------------- */
/* vpn packet structure:
[vpn-header][zlib-compressed-payload][0-to-XFER_BLOCKSIZE-1-padding-zero-bytes][vpn-tailer]...[vpn-tailer]
|<------------------------------------ blowfish encrypted ---------------------------------------------->|
*/

struct __attribute__ ((aligned(4), packed)) vpn_header /* this describes the entire VPN packet */
{                                       /* all fields are transferred in network byte order */
  unsigned int       data_hash[3];      /* 96 bit hash of everything below, including the rest of the header, payload and tailers */
  unsigned long long sequence_id;       /* 64 bit (32 bit time, 32 bit counter) monotonically increasing sequence number for this packet */
  unsigned short int data_length;       /* 16 bit length of compressed payload data contained in this packet, in bytes */
  unsigned char      flags;             /* bitwise combination of VHF_... */
  unsigned char      tailers_count;     /* number of XFER_BLOCKSIZE-sized tailers on this packet */
#define VPN_HEADER_BLOCKS ((sizeof(struct vpn_header) + XFER_BLOCKSIZE - 1) / XFER_BLOCKSIZE)
#define VPN_HEADER_SIZE (VPN_HEADER_BLOCKS * XFER_BLOCKSIZE)
};

struct __attribute__ ((aligned(4), packed)) vpn_tailer /* each of these describes a single tun packet squeezed in this VPN packet */
{                                       /* all fields are transferred in network byte order */
  unsigned short int offset;
  unsigned short int length;
  unsigned int       unused_zero;
#define VPN_TAILER_BLOCKS ((sizeof(struct vpn_tailer) + XFER_BLOCKSIZE - 1) / XFER_BLOCKSIZE)
#define VPN_TAILER_SIZE (VPN_TAILER_BLOCKS * XFER_BLOCKSIZE)
};

#define PACKET_SIZE_BLOCKS(HEADPTR) (VPN_HEADER_BLOCKS + \
                                     XFER_BLOCKS((HEADPTR)->data_length) + \
                                     ((HEADPTR)->tailers_count * VPN_TAILER_BLOCKS))

#define PACKET_SIZE(HEADPTR) (PACKET_SIZE_BLOCKS(HEADPTR) * XFER_BLOCKSIZE)

#define MIN_VPN_PACKET_OVERHEAD (sizeof(struct ip) + VPN_HEADER_SIZE)

/* VPN header flags */

#define VHF_NEED_MORE_PINGS 0x80 /* set if the sender is using ICMP responses, and there is none available */
#define VHF_SWITCHING_KEYS  0x40 /* set if the sender has a new set of keys pending rotation */

/* ------------------------------------------------------------------------------------- */

extern unsigned char tun_buf[BUFSIZE];                          /* buffered packet bodies pending to be sent */
extern unsigned int tun_q[MAX_QUEUED_PACKETS];                  /* sizes of the packets currently queued in tun_buf */
extern unsigned int tun_q_length;                               /* number of packets currently queued in tun_buf */
extern unsigned int tun_q_bytes;                                /* total size of packets currently queued in tun_buf in bytes */
extern unsigned int tun_q_timeout;                              /* ms elapsed since queue was last empty */
extern unsigned int q_delay_ms;                                 /* ms between forced queue flushes */
extern unsigned int q_tick_ms;                                  /* ms to add to the elapsed timeout per packet */

extern unsigned int sequence_id;                                /* packet counter, low 32 bits of outgoing packets sequence id */

extern int pid;                                                 /* pid of the current process */
extern sigjmp_buf breakpoint;                                   /* saved process context, is restored on signal */
extern int terminate;                                           /* aux flags */
extern int write_to_syslog;

extern char enc_key_filename[PATH_MAX+1];                       /* ex. /path/keyfile */
extern char auth_key_filename[PATH_MAX+1];                      /* ex. /path/keyfile */
extern char device_name[PATH_MAX+1];                            /* ex. /dev/tunX */
extern char pid_filename[PATH_MAX+1];                           /* ex. /var/run/nest.pid */

extern char err_buf[LINE_MAX+1];                                /* line buffer for errmsg() macro */

extern char tunnel_entry_address[LINE_MAX+1];                   /* ex. 10.0.0.1 */
extern char tunnel_exit_address[LINE_MAX+1];                    /* ex. 10.0.0.2 */
extern char tunnel_netmask[LINE_MAX+1];                         /* ex. 255.255.255.252 */
extern char source_address[LINE_MAX+1];                         /* ex. 123.45.67.89 */
extern char target_address[LINE_MAX+1];                         /* ex. 87.65.43.21 */
extern char tunnel_masquerade_source_address[LINE_MAX+1];       /* sort of a NAT address */
extern char tunnel_masquerade_destination_address[LINE_MAX+1];  /* sort of a NAT address */

extern struct sockaddr_in tunnel_entry_sockinfo;                /* above addresses DNS resolved */
extern struct sockaddr_in tunnel_exit_sockinfo;
extern struct sockaddr_in tunnel_netmask_sockinfo;
extern struct sockaddr_in target_sockinfo;
extern struct sockaddr_in source_sockinfo;
extern struct sockaddr_in tunnel_masquerade_source_sockinfo;
extern struct sockaddr_in tunnel_masquerade_destination_sockinfo;
extern struct sockaddr_in blank_sockinfo;

extern int tunnel_masquerade_source;                            /* source IP address should be replaced on IP packets injected into LAN */
extern int tunnel_masquerade_destination;                       /* destination -//- */

extern struct ifreq if_req_tun;                                 /* aux. structures for setting up */
extern struct ifaliasreq if_aliasreq_tun;

extern int network_mtu;                                         /* MTU on network interface, specified with -M */
extern int network_payload_size;                                /* estimate max. raw bytes VPN packet is capable of carrying */
extern int tunnel_mtu;                                          /* suggested MTU on tunnel device */

extern int network;                                             /* handle to an open raw socket, is dup'ed to 0 */
extern int tunnel;                                              /* handle to an open tunnel device, is dup'ed to 1 */
extern int protocol;                                            /* ip protocol number to tag VPN packets with */

extern unsigned short int divert_port_number;                   /* port number to bind divert socket to, host format */

extern int send_mode;                                           /* one of the SEND_... constants */

/* ------------------------------------------------------------------------------------- */
int read_params(int argc, char* argv[]);
/* ------------------------------------------------------------------------------------- */
int first_init();
/* ------------------------------------------------------------------------------------- */
int init();
/* ------------------------------------------------------------------------------------- */
int done();
/* ------------------------------------------------------------------------------------- */
int last_done();
/* ------------------------------------------------------------------------------------- */
void termhandler(int signo);
/* ------------------------------------------------------------------------------------- */
int set_sig_handlers();
/* ------------------------------------------------------------------------------------- */
int unblock_pending_signals(int action);
/* ------------------------------------------------------------------------------------- */
/* Reads the specified files, derives encryption key from sha1(enc_key) bytes,
   and authentication key from unfinalized sha1(auth_key).
*/
int read_keys(char* enc_key_filename, char* auth_key_filename);
/* ------------------------------------------------------------------------------------- */
int write_pid_file();
/* ------------------------------------------------------------------------------------- */
int remove_pid_file();
/* ------------------------------------------------------------------------------------- */
int open_tunnel_device(char* device_name);
/* ------------------------------------------------------------------------------------- */
int close_tunnel_device();
/* ------------------------------------------------------------------------------------- */
int prepare_addresses();
/* ------------------------------------------------------------------------------------- */
int tunnel_no_return();
/* ------------------------------------------------------------------------------------- */
int close_streams();
/* ------------------------------------------------------------------------------------- */
int open_network();
/* ------------------------------------------------------------------------------------- */
int close_network();
/* ------------------------------------------------------------------------------------- */
/* Main function. Receives packets from both inside the LAN and from the outside WAN.
Loops forever, processing one packet per loop. Only returns on fatal initialization
error, when interrupted by a signal, gets restarted from main().
*/
int tunnel_no_return();
/* ------------------------------------------------------------------------------------- */
/* Makes a decision on whether the packet should be queued, sent with all the queued packets
so far, sent alone or be dropped.
*/
int tun_packet_switch(struct ip* p_ip, unsigned short int ip_packet_length);
/* ------------------------------------------------------------------------------------- */

#endif

