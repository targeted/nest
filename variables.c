/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

/* Home for those variables declared in nest.h that have no better place to live. */

#include "nest.h"

unsigned char tun_buf[BUFSIZE];
unsigned int tun_q[MAX_QUEUED_PACKETS];
unsigned int tun_q_length;
unsigned int tun_q_bytes;
unsigned int tun_q_timeout;
unsigned int q_delay_ms = Q_DELAY_MS;
unsigned int q_tick_ms = Q_DELAY_MS / MAX_QUEUED_PACKETS;

unsigned int sequence_id;

int pid;
sigjmp_buf breakpoint;
int terminate = 0;
int write_to_syslog = 0;

char enc_key_filename[PATH_MAX+1];
char auth_key_filename[PATH_MAX+1];
char device_name[PATH_MAX+1];
char pid_filename[PATH_MAX+1];

char err_buf[LINE_MAX+1];

char tunnel_entry_address[LINE_MAX+1];
char tunnel_exit_address[LINE_MAX+1];
char tunnel_netmask[LINE_MAX+1];
char target_address[LINE_MAX+1];
char source_address[LINE_MAX+1];
char tunnel_masquerade_source_address[LINE_MAX+1];
char tunnel_masquerade_destination_address[LINE_MAX+1];

struct sockaddr_in tunnel_entry_sockinfo;
struct sockaddr_in tunnel_exit_sockinfo;
struct sockaddr_in tunnel_netmask_sockinfo;
struct sockaddr_in target_sockinfo;
struct sockaddr_in source_sockinfo;
struct sockaddr_in tunnel_masquerade_source_sockinfo;
struct sockaddr_in tunnel_masquerade_destination_sockinfo;
struct sockaddr_in blank_sockinfo;

int tunnel_masquerade_source;
int tunnel_masquerade_destination;

struct ifreq if_req_tun;
struct ifaliasreq if_aliasreq_tun;

int tunnel;
int network;
int protocol;

int network_mtu;
int network_payload_size;
int tunnel_mtu;

unsigned short int divert_port_number;

int send_mode;
