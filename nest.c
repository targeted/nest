/* Nest 3.3 (c) Dmitry Dvoinikov, crypto portions (c) Eric Young */
/* See LICENSE for more information */

/* Main program file. See routine tunnel_no_return() for most understanding impact. */

#include "nest.h"
#include "crypto.h"
#include "replay.h"
#include "debug_routines.h"
#include "pkt_routines.h"
#include "interface_routines.h"
#include "utilities.h"

/* ------------------------------------------------------------------------------------- */

int main(int argc, char* argv[])
{

    /* running as foreground process */

    TRY(read_params(argc, argv));
    TRY(prepare_addresses());
    TRY(unblock_pending_signals(SIG_BLOCK));
    TRY(set_sig_handlers());
    TRY(close_streams());

    if (daemon(NO_CHROOT, NO_STD_CLOSE) == -1) { err("daemon()"); return 1; }

    /* running as a daemon */

    TRY(first_init());
    TRY(write_pid_file());

    while (terminate == 0)
    {

        TRY(init());

        if (sigsetjmp(breakpoint, 0) == 0)
        {
            TRY(unblock_pending_signals(SIG_UNBLOCK));
            TRY(tunnel_no_return());
        }

        TRY(done());

    }

    TRY(remove_pid_file());
    TRY(last_done());

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int read_params(int argc, char* argv[])
{

    char ch, buf[256];

    if (argc == 1)
    {
        errmsg("\n"
               "Nest 3.3, point-to-point IP VPN tunnel.\n"
               "http://www.targeted.org/nest/\n"
               "\n"
               "Usage:\n"
               "nest -s tunnel.entry.virtual.address\n"
               "     -d tunnel.exit.virtual.address\n"
               "     -m tunnel.netmask                optional, default = 255.255.255.252\n"
               "     -r this.peer.real.address\n"
               "     -g remote.peer.real.address\n"
               "     -t /dev/tunX\n"
               "     -k /pre/shared/secret/enc_key\n"
               "     -K /pre/shared/secret/auth_key   optional, default = same as enc_key\n"
               "     -P /path/pidfile                 optional, default = /var/run/nest.pid\n"
               "     -p ip_protocol_number            optional, default = 99 (ipip)\n"
               "     -e req|resp                      optional, may only be used with -p 1\n"
               "     -D divert_port_number            optional, must be used with -e resp\n"
               "     -n replace.source.ip.with        optional, default = not specified\n"
               "     -N replace.destination.ip.with   optional, default = not specified\n"
               "     -q queue_delay_in_milliseconds   optional, default = 100, range 0-1000\n"
               "     -z zlib_compression_level        optional, default = 6, range 0-9\n"
               "     -y replay_window_size_in_seconds optional, default = 60, range 0-3600\n"
               "     -M network_mtu_in_bytes          optional, default = 1500, rg 576-1500\n"
               "\n"
               "Example using any regular protocol (not ICMP):\n"
               "root@host1> nest -s 10.0.0.1 -d 10.0.0.2 -r host1 -g host2 -t /dev/tun0 -k keyfile\n"
               "root@host2> nest -s 10.0.0.2 -d 10.0.0.1 -r host2 -g host1 -t /dev/tun0 -k keyfile\n"
               "\n"
               "Example using ICMP protocol (host1 can ping host2, but not necessarily vice versa):\n"
               "root@host1> nest -s 10.0.0.1 -d 10.0.0.2 -r host1 -g host2 -p 1 -e req -q 200\n"
               "                 -t /dev/tun0 -k keyfile\n"
               "root@host2> nest -s 10.0.0.2 -d 10.0.0.1 -r host2 -g host1 -p 1 -e resp -q 200\n"
               "                 -D 40000 -t /dev/tun0 -k keyfile\n"
               "root@host2> ipfw add divert 40000 icmp from host2 to host1 in via if0 icmptype 8\n"
               "\n"
               "See README for more information.\n"
               "\n"
               "Copyright (c) 2001-2017 Dmitry Dvoinikov (dmitry@targeted.org)\n"
               "Crypto portions copyright (c) 1995-1998 Eric Young (eay@cryptsoft.com)\n"
               "See LICENSE for more information.\n");
        return 1;
    }

    tunnel_entry_address[0] = '\0';
    tunnel_exit_address[0] = '\0';
    source_address[0] = '\0';
    target_address[0] = '\0';
    enc_key_filename[0] = '\0';
    auth_key_filename[0] = '\0';
    device_name[0] = '\0';
    strcpy(pid_filename, PID_FILENAME);
    strcpy(tunnel_netmask, "255.255.255.252");
    zlib_compression_level = Z_DEFAULT_COMPRESSION;
    protocol = PROTO;
    network_mtu = DEFAULT_NETWORK_MTU;
    send_mode = SEND_NORMAL;
    divert_port_number = 0;
    tunnel_masquerade_source = 0;
    tunnel_masquerade_destination = 0;

    while ((ch = getopt(argc, argv, "k:K:t:s:d:r:g:m:p:P:q:e:D:N:n:y:z:M:")) != -1)
    switch (ch)
    {
        case 'k':
            strncpy(enc_key_filename, optarg, PATH_MAX);
            break;
        case 'K':
            strncpy(auth_key_filename, optarg, PATH_MAX);
            break;
        case 't':
            strncpy(device_name, optarg, PATH_MAX);
            break;
        case 's':
            strncpy(tunnel_entry_address, optarg, LINE_MAX);
            break;
        case 'd':
            strncpy(tunnel_exit_address, optarg, LINE_MAX);
            break;
        case 'r':
            strncpy(source_address, optarg, LINE_MAX);
            break;
        case 'g':
            strncpy(target_address, optarg, LINE_MAX);
            break;
        case 'p':
            protocol = atoi(optarg);
            if (protocol < 0 || protocol > IPPROTO_MAX)
            {
                sprintf(buf, "Invalid protocol number, must be in range 0-%d.", IPPROTO_MAX);
                errmsg(buf);
                return 1;
            }
            break;
        case 'P':
            strncpy(pid_filename, optarg, PATH_MAX);
            break;
        case 'm':
            strncpy(tunnel_netmask, optarg, LINE_MAX);
            break;
        case 'q':
            q_delay_ms = atoi(optarg);
            if (q_delay_ms < 0 || q_delay_ms > Q_DELAY_MS_MAX || (q_delay_ms > 0 && q_delay_ms < Q_DELAY_MS_MIN))
            {
                sprintf(buf, "Invalid queue timeout value, must be in range %d to %d ms, or zero for no queueing.",
                        Q_DELAY_MS_MIN, Q_DELAY_MS_MAX);
                errmsg(buf);
                return 1;
            }
            q_tick_ms = q_delay_ms / MAX_QUEUED_PACKETS; /* the above check guarantees q_tick_ms is at least 1 (or zero if q_delay_ms is zero) */
            break;
        case 'e':
            if (strcmp(optarg, "req") == 0)
            {
                send_mode = SEND_WITH_ECHO_REQUEST;
                break;
            }
            else if (strcmp(optarg, "resp") == 0)
            {
                send_mode = SEND_WITH_ECHO_RESPONSE;
                break;
            }
            else
            {
                errmsg("Invalid ICMP send mode, must be either 'req' or 'resp'.");
                return 1;
            }
        case 'D':
            divert_port_number = atoi(optarg);
            break;
        case 'n':
            tunnel_masquerade_source = 1;
            strncpy(tunnel_masquerade_source_address, optarg, LINE_MAX);
            break;
        case 'N':
            tunnel_masquerade_destination = 1;
            strncpy(tunnel_masquerade_destination_address, optarg, LINE_MAX);
            break;
        case 'y':
            replay_window_sec = atoi(optarg);
            if (replay_window_sec > MAX_REPLAY_WINDOW_SEC)
            {
                sprintf(buf, "Invalid replay window size, must not exceed %d seconds.", MAX_REPLAY_WINDOW_SEC);
                errmsg(buf);
                return 1;
            }
            break;
        case 'z':
            zlib_compression_level = atoi(optarg);
            if (zlib_compression_level < 0 || zlib_compression_level > 9)
            {
                errmsg("Invalid zlib compression level, must be in range 0-9.");
                return 1;
            }
            break;
        case 'M':
            network_mtu = atoi(optarg);
            if (network_mtu < 576 || network_mtu > DEFAULT_NETWORK_MTU)
            {
                sprintf(buf, "Invalid network MTU, must be in range 576-%d.", DEFAULT_NETWORK_MTU);
                errmsg(buf);
                return 1;
            }
            break;
        default:
            break;
    }

    /* check if all the parameters are set correctly */

    if (tunnel_entry_address[0] == '\0') { errmsg("Tunnel source address (-s) must be specified."); return 1; }
    if (tunnel_exit_address[0] == '\0') { errmsg("Tunnel destination address (-d) must be specified."); return 1; }
    if (source_address[0] == '\0') { errmsg("Source address (-r) must be specified."); return 1; }
    if (target_address[0] == '\0') { errmsg("Target address (-g) must be specified."); return 1; }
    if (enc_key_filename[0] == '\0') { errmsg("Encryption key filename (-k) must be specified."); return 1; }
    if (device_name[0] == '\0') { errmsg("Tunneling device (-t) must be specified."); return 1; }

    if ((protocol != IPPROTO_ICMP && send_mode != SEND_NORMAL) ||
        (protocol == IPPROTO_ICMP && send_mode == SEND_NORMAL))
    {
        errmsg("ICMP protocol (-p 1) must be used with the icmp (-e req|resp) sending modes.");
        return 1;
    }

    if ((send_mode != SEND_WITH_ECHO_RESPONSE && divert_port_number != 0) ||
        (send_mode == SEND_WITH_ECHO_RESPONSE && divert_port_number == 0))
    {
        errmsg("Divert port (-D) must be used with response (-e resp) sending mode.");
        return 1;
    }

    if (send_mode == SEND_WITH_ECHO_REQUEST && q_delay_ms == 0)
    {
        errmsg("Queue timeout (-q) must be > 0 when using ICMP requests for sending, a ping will be sent out at least once in a specified time.");
        return 1;
    }

    if (send_mode == SEND_WITH_ECHO_RESPONSE && q_delay_ms == 0)
    {
        errmsg("Queue timeout (-q) must be > 0 when using ICMP responses for sending, the queue will time out in a specified time.");
        return 1;
    }

    network_payload_size = network_mtu - MIN_VPN_PACKET_OVERHEAD;      /* raw bytes per packet */
    if (protocol == IPPROTO_ICMP) network_payload_size -= SIZEOF_ICMP; /* sending with ICMP packets adds certain overhead */
    tunnel_mtu = network_payload_size * 99 / 100 - 12;                 /* calculate tunnel MTU for the worst negative zlib compression case */

    memset(&blank_sockinfo, 0, sizeof(struct sockaddr_in));            /* this structure will be used with sendto() */
    blank_sockinfo.sin_family = AF_INET;                               /* via divert socket, therefore the port number has this */
    blank_sockinfo.sin_len = sizeof(struct sockaddr_in);               /* "special" meaning of the ipfw rule number to start */
    blank_sockinfo.sin_addr.s_addr = INADDR_ANY;                       /* filtering for the injected packet from. I leave it as 0 */
    blank_sockinfo.sin_port = 0;                                       /* so that the injected packet is fully processed */

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int first_init()
{

    srandomdev();                                /* unsafe PRNG, only used with generating non-critical randoms */

    TRY(open_network());                         /* open network first so that it gets handle 0 */
    TRY(open_tunnel_device(device_name));        /* tunnel gets 1 */

    pid = getpid();

    if (send_mode == SEND_WITH_ECHO_REQUEST)     /* used for tagging ICMP packets */
    {
        icmp_request_seq = 0;
    }

    sequence_id = ((unsigned)random()) % 0xff000000; /* initialize 32 bit packet counter with random value, see seal_packet() */

    keys_loaded = 0;                             /* no current keys */
    switch_keys_at = 0;                          /* and no pending keys */

#ifdef _DEBUG
    debug = fopen("nest.log", "w");              /* only after that do we open the log file */
    setvbuf(debug, 0, _IOLBF, 0);
#endif

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int init()
{

    unsigned int i;

    tun_q_length = 0;                                /* reset packet queue */
    tun_q_bytes = 0;                                 /* some packets may be discarded, */
    tun_q_timeout = 0;                               /* but hey, it's signal or what ? */

    replay_offset = 0;                               /* reset replay checking structures */
    for (i = 0; i < REPLAY_WINDOW_SIZE; ++i)         /* this is necessary because otherwise there would have been */
    {                                                /* no other way of resuming VPN if either side occassionally */
        replay_window[i] = 0;                        /* adjusts time backwards, the replay bitmap would have */
    }                                                /* blocked any further packets regardless of -q value */

    for (i = 0; i < ZALLOC_COUNT; ++i)               /* clear static zlib memory pool */
    {
        zalloc_map[i] = 0;
    }

    if (send_mode == SEND_WITH_ECHO_RESPONSE)        /* clear all available responses */
    {
        icmp_responses_count = 0;
        icmp_response_index = 0;
    }

    TRY(read_keys(enc_key_filename, auth_key_filename)); /* (re)read the (updated) keys */

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int done()
{
    return 0;
}

/* ------------------------------------------------------------------------------------- */

int last_done()
{

#ifdef _DEBUG
    fclose(debug);
#endif

#ifndef NO_SYSLOG
    closelog();
#endif

    TRY(close_tunnel_device());
    TRY(close_network());

    return 0;

}

/* ------------------------------------------------------------------------------------- */

void termhandler(int signo)
{
    if (signo != SIGHUP) terminate = 1;
    siglongjmp(breakpoint, 0);
}

/* ------------------------------------------------------------------------------------- */

int set_sig_handlers()
{

    struct sigaction sigact, osigact;

    sigact.sa_handler = termhandler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);

    TRY(sigaction(SIGINT,  &sigact, &osigact));
    TRY(sigaction(SIGTERM, &sigact, &osigact));
    TRY(sigaction(SIGHUP,  &sigact, &osigact));

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int unblock_pending_signals(int action)
{

    sigset_t sigs, osigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGHUP);

    TRY(sigprocmask(action, &sigs, &osigs));

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int read_keys(char* enc_key_filename, char* auth_key_filename)
{

    int enc_key_file, auth_key_file, rd;
    SHA_CTX enc_hash_context;
    unsigned char enc_key_hash[SHA_DIGEST_LENGTH];

#ifdef _DEBUG
    SHA_CTX tmp_hash_context;
    unsigned char auth_key_hash[SHA_DIGEST_LENGTH];
#endif

    unsigned char buf[1024];

    /* the keys will be loaded either as current or as pending */

    BF_KEY* p_bf_key;
    SHA_CTX* p_auth_hash_context;

    if (keys_loaded == 0 || replay_window_sec == 0) /* initial loading or the entire thing is disabled */
    {
        p_bf_key = &bf_key;
        p_auth_hash_context = &auth_hash_context;
    }
    else /* the new keys are being loaded, will be pending for a while */
    {
        p_bf_key = &new_bf_key;
        p_auth_hash_context = &new_auth_hash_context;
    }

    /* open and read the specified encryption key file */

    if ((enc_key_file = open(enc_key_filename, O_RDONLY)) == -1) { err("open(enc_key)"); return 1; }

    SHA1_Init(&enc_hash_context);

    while ((rd = read(enc_key_file, buf, sizeof(buf))) > 0)
    {
        SHA1_Update(&enc_hash_context, buf, rd);
    }

    close(enc_key_file);

    if (rd < 0) { err("read(enc_key)"); return 1; }

    /* this is the default behavior, using encryption key also for */
    /* authentication unless separate authentication key is specified */

    memmove(p_auth_hash_context, &enc_hash_context, sizeof(SHA_CTX));

    /* use key file hash as raw key material for generating blowfish key schedule */

    SHA1_Final(enc_key_hash, &enc_hash_context);
    BF_set_key(p_bf_key, SHA_DIGEST_LENGTH, enc_key_hash);

    /* override the authentication key if a separate key file is specified */

    if (auth_key_filename[0] != '\0')
    {

        /* open and read the specified authentication key file */

        if ((auth_key_file = open(auth_key_filename, O_RDONLY)) == -1) { err("open(auth_key)"); return 1; }

        SHA1_Init(p_auth_hash_context);

        while ((rd = read(auth_key_file, buf, sizeof(buf))) > 0)
        {
            SHA1_Update(p_auth_hash_context, buf, rd);
        }

        close(auth_key_file);

        if (rd < 0) { err("read(auth_key)"); return 1; }

    }

#ifdef _DEBUG
    fprintf(debug, "Loaded new keys:\n");
    dump_data("h(enc_key)", enc_key_hash, SHA_DIGEST_LENGTH);
    memcpy(&tmp_hash_context, p_auth_hash_context, sizeof(SHA_CTX));
    SHA1_Final(auth_key_hash, &tmp_hash_context);
    dump_data("h(auth_key)", auth_key_hash, SHA_DIGEST_LENGTH);
#endif

    if (keys_loaded == 1 && replay_window_sec > 0) /* new keys will be pending */
    {
#ifdef _DEBUG
        fprintf(debug, "The new keys will be pending for %d seconds\n", replay_window_sec);
#endif
        switch_keys_at = time(0) + replay_window_sec;
    }
    else
    {
#ifdef _DEBUG
        fprintf(debug, "The new keys are immediately in effect\n");
#endif
    }

    keys_loaded = 1;

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int write_pid_file()
{

    FILE *fpid;

    if ((fpid = fopen(pid_filename, "w+")) == NULL) { err("create(pidfile)"); return 1; }
    fprintf(fpid, "%d", pid);
    fclose(fpid);

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int remove_pid_file()
{
    return -remove(pid_filename);
}

/* ------------------------------------------------------------------------------------- */

int open_network()
{

    struct sockaddr_in port_only;

    /* open and connect raw network socket */

    if (send_mode == SEND_WITH_ECHO_RESPONSE)
    {
        if ((network = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) { err("socket(net)"); return 1; }
    }
    else
    {
        if ((network = socket(AF_INET, SOCK_RAW, protocol)) == -1) { err("socket(net)"); return 1; }
    }

    if (network != 0) { if (dup2(network, 0) == -1) { err("dup2(net)"); return 1; } close(network); network = 0; }
    if (setsockopt(network, IPPROTO_IP, IP_OPTIONS, 0, 0) == -1) { err("setsockopt(IP_OPTIONS)"); return 1; }

    if (send_mode == SEND_WITH_ECHO_RESPONSE)
    {
        port_only.sin_family = AF_INET;
        port_only.sin_addr.s_addr = INADDR_ANY;
        port_only.sin_port = htons(divert_port_number);
        memset(port_only.sin_zero, 0, sizeof(port_only.sin_zero));
        if (bind(network, (struct sockaddr*)&port_only, sizeof(struct sockaddr_in)) == -1) { err("bind(net)"); return 1; }
    }
    else
    {
        if (connect(network, (struct sockaddr *)&target_sockinfo, sizeof(struct sockaddr_in)) == -1) { err("connect(net)"); return 1; }
    }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int close_network()
{
    if (close(network) == -1) { err("close(net)"); return 1; }
    return 0;
}

/* ------------------------------------------------------------------------------------- */

int open_tunnel_device(char* name)
{

    int s, if_flags;

    if ((tunnel = open(name, O_RDWR)) == -1) { err("open(tun)"); return 1; }
    if (tunnel != 1) { if (dup2(tunnel, 1) == -1) { err("dup2(tun)"); return 1; } close(tunnel); tunnel = 1; }

    /* create temporary socket */

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { err("socket()"); close(tunnel); return 1; }

    /* get interface flags */

    if (ioctl(s, SIOCGIFFLAGS, &if_req_tun) == -1) { err("ioctl(SIOCGIFFLAGS)"); close(tunnel); close(s); return 1; }
    if_flags = if_req_tun.ifr_flags;

    if ((if_flags & IFF_POINTOPOINT) == 0) { errmsg("Not a point-to-point device."); close(tunnel); close(s); return 1; }

    /* bring interface down */

    if_req_tun.ifr_flags = if_flags & ~(IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &if_req_tun) == -1) { err("ioctl(SIOCSIFFLAGS)"); close(tunnel); close(s); return 1; }

    /* delete all current interface address(es) */

    while (ioctl(s, SIOCGIFADDR, &if_req_tun) != -1)
        if (ioctl(s, SIOCDIFADDR, &if_req_tun) == -1) { err("ioctl(SIOCDIFADDR)"); close(tunnel); close(s); return 1; }

    /* add interface address specified in command line */

    memcpy(&if_aliasreq_tun.ifra_addr, &tunnel_entry_sockinfo, sizeof(struct sockaddr_in));
    memcpy(&if_aliasreq_tun.ifra_broadaddr, &tunnel_exit_sockinfo, sizeof(struct sockaddr_in));
    memcpy(&if_aliasreq_tun.ifra_mask, &tunnel_netmask_sockinfo, sizeof(struct sockaddr_in));

    if (ioctl(s, SIOCAIFADDR, &if_aliasreq_tun) == -1) { err("ioctl(SIOCAIFADDR)"); close(tunnel); close(s); return 1; }

    /* adjust tunnel MTU so that the kernel guarantees we don't receive unacceptably large packets */

    if_req_tun.ifr_mtu = tunnel_mtu;
    if (ioctl(s, SIOCSIFMTU, &if_req_tun) == -1) { err("ioctl(SIOCSIFMTU)"); close(tunnel); close(s); return 1; }

    /* bring interface up */

    if_req_tun.ifr_flags = if_flags | (IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &if_req_tun) == -1) { err("ioctl(SIOCSIFFLAGS)"); close(tunnel); close(s); return 1; }

    /* close temporary socket */

    if (close(s) == -1) { err("close(socket)"); close(tunnel); return 1; }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int close_tunnel_device()
{

    int s, if_flags;

    /* create temporary socket */

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { err("socket()"); close(tunnel); return 1; }

    /* bring interface down */

    if (ioctl(s, SIOCGIFFLAGS, &if_req_tun) == -1) { err("ioctl(SIOCGIFFLAGS)"); close(tunnel); close(s); return 1; }
    if_flags = if_req_tun.ifr_flags;

    if_req_tun.ifr_flags = if_flags & ~(IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &if_req_tun) == -1) { err("ioctl(SIOCSIFFLAGS)"); close(tunnel); close(s); return 1; }

    /* delete all current interface address(es) */

    while (ioctl(s, SIOCGIFADDR, &if_req_tun) != -1)
        if (ioctl(s, SIOCDIFADDR, &if_req_tun) == -1) { err("ioctl(SIOCDIFADDR)"); close(tunnel); close(s); return 1; }

    /* close temporary socket */

    if (close(s) == -1) { err("close(socket)"); close(tunnel); return 1; }

    if (close(tunnel) == -1) { err("close(tun)"); return 1; }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int close_streams()
{

    TRY(close(STDIN_FILENO));
    TRY(close(STDOUT_FILENO));
    TRY(close(STDERR_FILENO));

    /* as soon as stderr os closed, connection to syslog must be established */
    /* so that errmsg macro keeps working */

#ifndef NO_SYSLOG
    openlog("nest", LOG_PID, LOG_DAEMON);
#endif
    write_to_syslog = 1;

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int resolve_address(char* addr, struct sockaddr_in *sockinfo)
{

    struct hostent *hostinfo;

    memset(sockinfo, 0, sizeof(struct sockaddr_in));

    sockinfo->sin_len = sizeof(struct sockaddr_in);
    sockinfo->sin_family = AF_INET;

    if ((sockinfo->sin_addr.s_addr = inet_addr(addr)) == INADDR_NONE)
    {
        if ((hostinfo = gethostbyname(addr)) == NULL) { err("gethostbyname()"); return 1; }
        if (hostinfo->h_addrtype != AF_INET) { errmsg("gethostbyname(): Invalid address type."); return 1; }
        memcpy(&(sockinfo->sin_addr), hostinfo->h_addr, hostinfo->h_length);
        if (sockinfo->sin_addr.s_addr == INADDR_NONE) { errmsg("gethostbyname(): Address not resolved."); return 1; }
    }

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int prepare_addresses()
{

    char* short_name;

    TRY(resolve_address(tunnel_entry_address, &tunnel_entry_sockinfo));
    TRY(resolve_address(tunnel_exit_address, &tunnel_exit_sockinfo));
    TRY(resolve_address(tunnel_netmask, &tunnel_netmask_sockinfo));
    TRY(resolve_address(source_address, &source_sockinfo));
    TRY(resolve_address(target_address, &target_sockinfo));
    if (tunnel_masquerade_source == 1)
    {
        TRY(resolve_address(tunnel_masquerade_source_address, &tunnel_masquerade_source_sockinfo));
    }
    if (tunnel_masquerade_destination == 1)
    {
        TRY(resolve_address(tunnel_masquerade_destination_address, &tunnel_masquerade_destination_sockinfo));
    }

    if (strncmp(device_name, "/dev/", 5) == 0) short_name = device_name + 5; else short_name = device_name;
    strncpy(if_req_tun.ifr_name, short_name, IFNAMSIZ);
    strncpy(if_aliasreq_tun.ifra_name, short_name, IFNAMSIZ);

    return 0;

}

/* ------------------------------------------------------------------------------------- */

int tun_packet_switch(struct ip* p_ip, unsigned short int ip_packet_length)
{

    int bytes_to_free_up, packets_to_drop;

    /* check if we can send now, sending with ICMP responses requires special handling */

    if (send_mode == SEND_WITH_ECHO_RESPONSE) /* must have other side's pings */
    {

        if (remove_expired_icmp_responses() == 0) /* no pings available, can't send */
        {

            /* see if there is enough space in the queue to stack up this new incoming packet */
            /* we may need to drop some packets so that the _next_ packet could be received (invariant) */

            if (tun_q_length == MAX_QUEUED_PACKETS || tun_q_bytes > AVAIL_BUFSIZE - tunnel_mtu)
            {

                if (tun_q_length == MAX_QUEUED_PACKETS)
                {
                    packets_to_drop = 1;
                    if (AVAIL_BUFSIZE - (tun_q_bytes - tun_q[0]) >= tunnel_mtu)
                    {
                        bytes_to_free_up = 0;
                    }
                    else
                    {
                        bytes_to_free_up = tunnel_mtu - (AVAIL_BUFSIZE - (tun_q_bytes - tun_q[0]));
                    }
                }
                else
                {
                    packets_to_drop = 0;
                    bytes_to_free_up = tunnel_mtu - (AVAIL_BUFSIZE - tun_q_bytes);
                }

                while (bytes_to_free_up > 0 && packets_to_drop < tun_q_length) /* bytes_to_free_up is signed and thus can fall below 0 */
                {
                    bytes_to_free_up -= tun_q[packets_to_drop];
                    packets_to_drop += 1;
                }

                /* the oldest packets are now discarded, sad but true */

                _syslog(LOG_WARNING, "No pings from the other side, can't send, dropping %d queued packet(s) to free up space in the queue", packets_to_drop);
                remove_queued_packets(0, packets_to_drop);

            }

            return PKT_DELAY;

        }

        /* otherwise some responses are available and we proceed to sending as usual */

    }

    if (q_delay_ms == 0 || tun_q_length == MAX_QUEUED_PACKETS || tun_q_bytes > AVAIL_BUFSIZE - tunnel_mtu)
    {
        return PKT_SEND; /* the queue is full or packets go without any queueing */
    }

    switch (p_ip->ip_p)
    {
    case IPPROTO_ICMP:       /* ICMP packets are not queued up, but sent out-of-band immediately */
        return PKT_SEND_OOB;
    case IPPROTO_TCP:        /* small TCP packets flush the queue */
        if (ip_packet_length < (p_ip->ip_hl << 2) + sizeof(struct tcphdr) + SMALL_PACKET_THRESHOLD)
        {
            return PKT_SEND;
        }
        break;
    case IPPROTO_UDP:        /* small UDP packets flush the queue */
        if (ip_packet_length < (p_ip->ip_hl << 2) + sizeof(struct udphdr) + SMALL_PACKET_THRESHOLD)
        {
            return PKT_SEND;
        }
        break;
    default:
        break;
    }

    return PKT_DELAY; /* all other packets are queued up */

}

/* ------------------------------------------------------------------------------------- */

int tunnel_no_return()
{

    fd_set rd_set;                       /* vars for select */
    int fd_ready;
    struct timeval tv;
    int can_read_tunnel, can_read_network;
    int need_fake_packet;                /* this only gets to work in SEND_WITH_ECHO_REQUEST sending mode */
    icmp_response_t icmp_response;

    static unsigned char net_buf[BUFSIZE];     /* buffer for receiving single network packet */
    static unsigned char inflate_buf[BUFSIZE]; /* buffer for decompressing received network packet */
    z_stream inflate_stream;                   /* zlib stream used for decompressing received vpn packets */

    int rd;                              /* bytes read */

    struct ip* p_ip;                     /* pointer to a checked to be valid IP packet */
    unsigned short int ip_packet_length; /* length of -//- */

    struct vpn_header *pkt_head;         /* utility pointers */

    unsigned char* packet_data;          /* describe the inflated data in inflate_buf */
    unsigned short int packet_data_length;

    struct vpn_tailer *pkt_tailer;       /* points to the packet tailer currently being processed */
    unsigned short int fragment_offset;  /* describe the fragment for a tailer currently being processed */
    unsigned short int fragment_length;

    unsigned int pkt_time;

    inflate_stream.zalloc = &zalloc;     /* initialize zlib compression context */
    inflate_stream.zfree = &zfree;
    inflate_stream.opaque = 0;
    if (inflateInit(&inflate_stream) != Z_OK) return 1;

    need_fake_packet = 0;

    while (1) /* loops forever, when interrupted by a signal, this function is restarted */
    {         /* so the system calls never return error with errno=EINTR or whatever */

        /* check for data on either tunnel or network */

        FD_ZERO(&rd_set); FD_SET(tunnel, &rd_set); FD_SET(network, &rd_set);
        tv.tv_sec = 0; tv.tv_usec = q_tick_ms * 1000;
        if ((fd_ready = select(2, &rd_set, NULL, NULL, q_tick_ms == 0 ? NULL : &tv)) < 0)
        {
            _syslog(LOG_WARNING, "select() failed: %m");
            continue;
        }

        can_read_tunnel = FD_ISSET(tunnel, &rd_set) ? 1 : 0;
        can_read_network = FD_ISSET(network, &rd_set) ? 1 : 0;

        /* charge the queue with a tick, proceed to flush if the queue times out */
        /* the queue is charged if (1) it's non-empty OR (2) sending with ICMP pings */

        if (q_tick_ms > 0 && (tun_q_length > 0 || send_mode == SEND_WITH_ECHO_REQUEST) &&
            (tun_q_timeout += q_tick_ms) >= q_delay_ms)
        {

            tun_q_timeout = 0;    /* reset the timeout */

            if (tun_q_length > 0) /* packet queue contains packets */
            {
                if (send_mode != SEND_WITH_ECHO_RESPONSE || /* can send now */
                    remove_expired_icmp_responses() > 0)
                {
                    flush_queued_packets(0, tun_q_length); /* send all the queue out */
                }
            }
            else if (send_mode == SEND_WITH_ECHO_REQUEST) /* even if the queue is empty, need to inject a fake packet */
            {
                need_fake_packet = 1;
            }

        }

        /* if the queue has been flushed on timeout, it's just empty now, and we proceed */

        if (need_fake_packet == 1) /* need to inject a fake tunnel packet just to send anything */
        {                          /* over the ICMP VPN to enable the other side to send */

            need_fake_packet = 0;  /* simulate a fake packet being read on the tunnel and sent OOB right away */

            if ((rd = fake_tun(tun_buf + tun_q_bytes, AVAIL_BUFSIZE - tun_q_bytes)) == -1)
            {
                _syslog(LOG_WARNING, "fake_tun() failed");
                continue;
            }

            tun_q[tun_q_length++] = rd;
            tun_q_bytes += rd;

            flush_queued_packets(tun_q_length - 1, 1);

        }

        if (can_read_tunnel == 1) /* plain packet is available */
        {

            /* invariant: there is enough space in the buffer to read an incoming packet */
            /* more formally: AVAIL_BUFSIZE - tun_q_bytes >= tunnel_mtu */

            if ((rd = read_tun(tunnel, tun_buf + tun_q_bytes, AVAIL_BUFSIZE - tun_q_bytes)) == -1)
            {
                _syslog(LOG_WARNING, "read_tun(%s) failed: %m", tunnel_entry_address);
                continue;
            }

            /* the read_tun function checks the read data to be a valid IP packet */

            p_ip = (struct ip*)(tun_buf + tun_q_bytes);
            ip_packet_length = rd;

            /* register the new packet on the queue */

            tun_q[tun_q_length++] = ip_packet_length;
            tun_q_bytes += ip_packet_length;

            /* tun_packet_switch tells the packet's destiny */

            switch (tun_packet_switch(p_ip, ip_packet_length)) /* tun_packet_switch also maintains the above mentioned invariant */
            {
            case PKT_DELAY:             /* keep all packets queued */
                break;
            case PKT_SEND:              /* send all the queued packets including the one just received */
                flush_queued_packets(0, tun_q_length);
                break;
            case PKT_SEND_OOB:          /* send the received packet alone, keep the queue */
                flush_queued_packets(tun_q_length - 1, 1);
                break;
            case PKT_DROP:              /* fallsthrough */
            default:
                remove_queued_packets(tun_q_length - 1, 1);
                break;
            }

        }

        if (can_read_network == 1) /* armoured VPN packet is incoming from the outside WAN */
        {

            /* read it to the special buffer, ignore all errors */

            if ((rd = read_net(network, net_buf, AVAIL_BUFSIZE,
                               send_mode == SEND_WITH_ECHO_RESPONSE ? &icmp_response : 0)) == -1) continue;

            /* check whether the packet is valid and is not being replayed */

            pkt_time = time(0);
            if (unseal_packet(net_buf, rd, pkt_time) != 0) continue;
            pkt_head = (struct vpn_header *)(net_buf);
            if (check_replay(pkt_head->sequence_id, pkt_time) != 0) continue;

            /* from this point on we are certain that the packet is valid and is not being replayed */

            if (send_mode == SEND_WITH_ECHO_RESPONSE)   /* register only a valid and not replayed ping */
            {                                           /* the attacker can still damage the unprotected ICMP header */
                register_icmp_response(&icmp_response); /* but this is something we can't protect against anyway */
            }

            /* decompress the payload */

            if (inflateReset(&inflate_stream) != Z_OK) continue;

            inflate_stream.next_in = (Bytef*)(((unsigned char*)pkt_head) + VPN_HEADER_SIZE);
            inflate_stream.avail_in = (uLongf)(pkt_head->data_length);
            inflate_stream.next_out = inflate_buf;
            inflate_stream.avail_out = AVAIL_BUFSIZE;
            if (inflate(&inflate_stream, Z_SYNC_FLUSH) != Z_OK ||
                inflate_stream.avail_in > 0 || inflate_stream.avail_out == 0) continue;

            packet_data = inflate_buf;
            packet_data_length = AVAIL_BUFSIZE - inflate_stream.avail_out;

            /* decompressed payload can still contain more than one "logical" packets */
            /* each of those packets has a tailer associated with it */

            if (pkt_head->tailers_count > 0) /* VPN packet has tailers, process them one by one */
            {

                pkt_tailer = (struct vpn_tailer *) /* points to the first packet's tailer */
                                ((unsigned char*)pkt_head + VPN_HEADER_SIZE + XFER_ROUNDUP(pkt_head->data_length));

                while (pkt_head->tailers_count > 0) /* process packet tailers */
                {

                    fragment_offset = ntohs(pkt_tailer->offset);
                    fragment_length = ntohs(pkt_tailer->length);

                    if (fragment_length == 0 || fragment_offset + fragment_length > packet_data_length) break;

                    if (fake_packet(packet_data + fragment_offset, fragment_length) == 0)
                    {
                        if (write_tun(tunnel, packet_data + fragment_offset, fragment_length) == -1)
                        {
                            _syslog(LOG_WARNING, "write_tun(%s) failed: %m", tunnel_entry_address);
                        }
                    }

                    pkt_tailer += 1;
                    pkt_head->tailers_count -= 1;

                }

            }
            else /* packet without tailers encapsulates exactly single packet */
            {
                if (fake_packet(packet_data, packet_data_length) == 0)
                {
                    if (write_tun(tunnel, packet_data, packet_data_length) == -1)
                    {
                        _syslog(LOG_WARNING, "write_tun(%s) failed: %m", tunnel_entry_address);
                    }
                }
            }

            /* see if any of the VPN packet's header flags require special attention */

            if (send_mode == SEND_WITH_ECHO_REQUEST &&        /* sender depends on our pings and */
                (pkt_head->flags & VHF_NEED_MORE_PINGS) != 0) /* sender has more packets to send */
            {
                need_fake_packet = 1; /* this flag will come into play on next loop pass */
            }

        }

    }

    errmsg("not reached");
    return 1;

}

/* ------------------------------------------------------------------------------------- */

