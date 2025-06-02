/*
 * fakehttp.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define VERSION "0.9.2"

#define E(...) logger(__func__, __FILE__, __LINE__, __VA_ARGS__)

static int g_sockfd = 0;
static int g_exit = 0;
static int g_repeat = 3;
static uint32_t g_fwmark = 512;
static uint32_t g_nfqnum = 512;
static uint8_t g_ttl = 3;
static const char *g_iface = NULL;
static const char *g_hostname = NULL;

static void print_usage(const char *name)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  -h <hostname>      hostname for obfuscation (required)\n"
            "  -i <interface>     either interface name (required)\n"
            "  -m <mark>          fwmark for bypassing the queue\n"
            "  -n <number>        netfilter queue number\n"
            "  -r <repeat>        duplicate generated packets for <repeat> "
            "times\n"
            "  -t <ttl>           TTL for generated packets\n"
            "\n"
            "FakeHTTP version " VERSION "\n",
            name);
}


static void logger(const char *funcname, const char *filename,
                   unsigned long line, const char *fmt, ...)
{
    va_list args;
    time_t t;
    char *stime;

    t = time(NULL);
    stime = ctime(&t);
    if (stime) {
        stime[strlen(stime) - 1] = '\0';
        fprintf(stderr, "%s ", stime);
    }

    fprintf(stderr, "[%s() - %s:%lu] ", funcname, filename, line);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
}


static void signal_handler(int sig)
{
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            g_exit = 1;
            break;
        default:
            break;
    }
}


static int signal_setup(void)
{
    struct sigaction sa;
    int res;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;

    res = sigaction(SIGPIPE, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    res = sigaction(SIGHUP, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = signal_handler;

    res = sigaction(SIGINT, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    res = sigaction(SIGTERM, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int execute_command(char **argv, int silent)
{
    int res, status, fd, i;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        E("ERROR: fork(): %s", strerror(errno));
        return -1;
    }

    if (!pid) {
        if (silent) {
            fd = open("/dev/null", O_WRONLY);
            if (fd < 0) {
                E("ERROR: open(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            res = dup2(fd, STDOUT_FILENO);
            if (res < 0) {
                E("ERROR: dup2(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            res = dup2(fd, STDERR_FILENO);
            if (res < 0) {
                E("ERROR: dup2(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        execvp(argv[0], argv);

        E("ERROR: execvp(): %s", strerror(errno));
        fprintf(stderr, "failed to execute: %s", argv[0]);
        for (i = 1; argv[i]; i++) {
            fprintf(stderr, " %s", argv[i]);
        }
        fputc('\n', stderr);
        fflush(stderr);

        _exit(EXIT_FAILURE);
    }

    if (waitpid(pid, &status, 0) < 0) {
        E("ERROR: waitpid(): %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    return -1;
}


static void ipt_rules_cleanup(void)
{
    size_t i, ipt_cmds_cnt;
    char *ipt_cmds[][32] = {
        {"iptables", "-t", "mangle", "-F", "FAKEHTTP", NULL},
        {"iptables", "-t", "mangle", "-D", "INPUT", "-j", "FAKEHTTP", NULL},
        {"iptables", "-t", "mangle", "-D", "FORWARD", "-j", "FAKEHTTP", NULL},
        {"iptables", "-t", "mangle", "-X", "FAKEHTTP", NULL}};

    ipt_cmds_cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);

    for (i = 0; i < ipt_cmds_cnt; i++) {
        execute_command(ipt_cmds[i], 1);
    }
}


static int ipt_rules_setup(void)
{
    char fwmark_str[32], nfqnum_str[32], iface_str[32];
    size_t i, ipt_cmds_cnt;
    int res;
    char *ipt_cmds[][32] = {
        {"iptables", "-t", "mangle", "-N", "FAKEHTTP", NULL},
        {"iptables", "-t", "mangle", "-I", "INPUT", "-j", "FAKEHTTP", NULL},
        {"iptables", "-t", "mangle", "-I", "FORWARD", "-j", "FAKEHTTP", NULL},

        /*
            exclude marked packets
        */
        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark", "--mark",
         fwmark_str, "-j", "CONNMARK", "--save-mark", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-m", "connmark",
         "--mark", fwmark_str, "-j", "CONNMARK", "--restore-mark", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark", "--mark",
         fwmark_str, "-j", "RETURN", NULL},

        /*
            exclude local IPs
        */
        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "0.0.0.0/8", "-j",
         "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "10.0.0.0/8",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "100.64.0.0/10",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "127.0.0.0/8",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "169.254.0.0/16",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "172.16.0.0/12",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "192.168.0.0/16",
         "-j", "RETURN", NULL},

        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-s", "224.0.0.0/3",
         "-j", "RETURN", NULL},

        /*
            send to nfqueue
        */
        {"iptables", "-t", "mangle", "-A", "FAKEHTTP", "-i", iface_str, "-p",
         "tcp", "--tcp-flags", "ACK,FIN,RST", "ACK", "-j", "NFQUEUE",
         "--queue-num", nfqnum_str, NULL}};

    ipt_cmds_cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);

    res = snprintf(fwmark_str, sizeof(fwmark_str), "%" PRIu32, g_fwmark);
    if (res < 0 || (size_t) res >= sizeof(fwmark_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    res = snprintf(nfqnum_str, sizeof(nfqnum_str), "%" PRIu32, g_nfqnum);
    if (res < 0 || (size_t) res >= sizeof(nfqnum_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    res = snprintf(iface_str, sizeof(iface_str), "%s", g_iface);
    if (res < 0 || (size_t) res >= sizeof(iface_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    for (i = 0; i < ipt_cmds_cnt; i++) {
        res = execute_command(ipt_cmds[i], 0);
        if (res) {
            E("ERROR: execute_command()");
            return -1;
        }
    }

    return 0;
}


static uint16_t chksum(void *pseudo, size_t pseudo_count, void *data,
                       size_t count)
{
    uint32_t sum = 0;
    uint8_t *ptr, b1, b2;

    if (pseudo_count % 2 != 0) {
        return 0;
    }

    ptr = pseudo;
    while (pseudo_count > 1) {
        b1 = *ptr++;
        b2 = *ptr++;
        sum += (b2 << 8) + b1;
        pseudo_count -= 2;
    }

    ptr = data;
    while (count > 1) {
        b1 = *ptr++;
        b2 = *ptr++;
        sum += (b2 << 8) + b1;
        count -= 2;
    }
    if (count > 0) {
        sum += *ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}


static uint16_t chksum_pseudo_ipv4(uint8_t protonum, void *data, size_t count,
                                   uint32_t saddr_be, uint32_t daddr_be)
{
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    } __attribute__((packed)) pseudo;

    pseudo.saddr = saddr_be;
    pseudo.daddr = daddr_be;
    pseudo.zero = 0;
    pseudo.protocol = protonum;
    pseudo.len = htons(count);

    return chksum(&pseudo, sizeof(pseudo), data, count);
}


static int make_pkt(char *buffer, size_t buffer_size, uint32_t saddr_be,
                    uint32_t daddr_be, uint16_t sport_be, uint16_t dport_be,
                    uint32_t seq_be, uint32_t ackseq_be, int psh,
                    char *tcp_payload, size_t tcp_payload_size)
{
    size_t pkt_len;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *tcppl;

    pkt_len = sizeof(*iph) + sizeof(*tcph) + tcp_payload_size;
    if (buffer_size < pkt_len + 1) {
        return -1;
    }

    iph = (struct iphdr *) buffer;
    tcph = (struct tcphdr *) (buffer + sizeof(*iph));
    tcppl = buffer + sizeof(*iph) + sizeof(*tcph);

    memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = sizeof(*iph) / 4;
    iph->tos = 0;
    iph->tot_len = htons(pkt_len);
    iph->id = ((rand() & 0xff) << 8) | (rand() & 0xff);
    iph->frag_off = htons(1 << 14 /* DF */);
    iph->ttl = g_ttl;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr_be;
    iph->daddr = daddr_be;

    memset(tcph, 0, sizeof(*tcph));
    tcph->source = sport_be;
    tcph->dest = dport_be;
    tcph->seq = seq_be;
    tcph->ack_seq = ackseq_be;
    tcph->doff = sizeof(*tcph) / 4;
    tcph->psh = psh;
    tcph->ack = 1;
    tcph->window = htons(0x0080);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    if (tcp_payload_size) {
        memcpy(tcppl, tcp_payload, tcp_payload_size);
    }

    iph->check = chksum(NULL, 0, iph, sizeof(*iph));
    tcph->check = chksum_pseudo_ipv4(IPPROTO_TCP, tcph,
                                     sizeof(*tcph) + tcp_payload_size,
                                     saddr_be, daddr_be);
    return pkt_len;
}


static int send_ack(uint32_t saddr_be, uint32_t daddr_be, uint16_t sport_be,
                    uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be)
{
    int pkt_len;
    ssize_t nbytes;
    char pkt_buff[1024];
    struct sockaddr_in dstaddr;

    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = daddr_be;

    pkt_len = make_pkt(pkt_buff, sizeof(pkt_buff), saddr_be, daddr_be,
                       sport_be, dport_be, seq_be, ackseq_be, 0, NULL, 0);
    if (pkt_len < 0) {
        E("ERROR: make_pkt()");
        return -1;
    }

    nbytes = sendto(g_sockfd, pkt_buff, pkt_len, 0,
                    (struct sockaddr *) &dstaddr, sizeof(dstaddr));
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int send_http(uint32_t saddr_be, uint32_t daddr_be, uint16_t sport_be,
                     uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be)
{
    static const char *http_fmt = "GET / HTTP/1.1\r\n"
                                  "Host: %s\r\n"
                                  "Accept: */*\r\n"
                                  "\r\n";

    int http_len, pkt_len;
    ssize_t nbytes;
    char http_buff[512], pkt_buff[1024];
    struct sockaddr_in dstaddr;

    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = daddr_be;

    http_len = snprintf(http_buff, sizeof(http_buff), http_fmt, g_hostname);
    if (http_len < 0 || (size_t) http_len >= sizeof(http_buff)) {
        E("ERROR: snprintf()");
        return -1;
    }

    pkt_len = make_pkt(pkt_buff, sizeof(pkt_buff), saddr_be, daddr_be,
                       sport_be, dport_be, seq_be, ackseq_be, 1, http_buff,
                       http_len);
    if (pkt_len < 0) {
        E("ERROR: make_pkt()");
        return -1;
    }

    nbytes = sendto(g_sockfd, pkt_buff, pkt_len, 0,
                    (struct sockaddr *) &dstaddr, sizeof(dstaddr));
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    uint32_t pkt_id, ack_new;
    int res, i, pkt_len, iph_len, tcph_len, tcp_payload_len;
    struct nfqnl_msg_packet_hdr *ph;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *pkt_data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    (void) nfmsg;
    (void) data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        E("ERROR: nfq_get_msg_packet_hdr()");
        return -1;
    }

    pkt_id = ntohl(ph->packet_id);
    pkt_data = NULL;
    pkt_len = nfq_get_payload(nfa, &pkt_data);
    if (pkt_len < 0 || !pkt_data) {
        E("ERROR: nfq_get_payload()");
        goto ret_accept;
    }

    if ((size_t) pkt_len < sizeof(*iph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        goto ret_accept;
    }

    iph = (struct iphdr *) pkt_data;
    iph_len = iph->ihl * 4;

    if ((size_t) iph_len < sizeof(*iph)) {
        E("ERROR: invalid IP header length: %d", iph_len);
        goto ret_accept;
    }

    if (iph->protocol != IPPROTO_TCP) {
        E("ERROR: not a TCP packet (protocol %d)", (int) iph->protocol);
        goto ret_accept;
    }

    if ((size_t) pkt_len < iph_len + sizeof(*tcph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        goto ret_accept;
    }

    tcph = (struct tcphdr *) (pkt_data + iph_len);
    tcph_len = tcph->doff * 4;

    if (!inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip))) {
        strncpy(src_ip, "INVALID", sizeof(src_ip) - 1);
        src_ip[sizeof(src_ip) - 1] = '\0';
    }
    if (!inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip))) {
        strncpy(dst_ip, "INVALID", sizeof(dst_ip) - 1);
        src_ip[sizeof(src_ip) - 1] = '\0';
    }

    tcp_payload_len = pkt_len - iph_len - tcph_len;

    if (tcph->syn && tcph->ack) {
        E("%s:%u ===SYN-ACK===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
          ntohs(tcph->dest));

        ack_new = ntohl(tcph->seq);
        ack_new++;
        ack_new = htonl(ack_new);

        for (i = 0; i < g_repeat; i++) {
            res = send_ack(iph->daddr, iph->saddr, tcph->dest, tcph->source,
                           tcph->ack_seq, ack_new);
            if (res < 0) {
                E("ERROR: send_ack()");
                goto ret_accept;
            }
        }
        E("%s:%u <===ACK(*)=== %s:%u", src_ip, ntohs(tcph->source), dst_ip,
          ntohs(tcph->dest));

        for (i = 0; i < g_repeat; i++) {
            res = send_http(iph->daddr, iph->saddr, tcph->dest, tcph->source,
                            tcph->ack_seq, ack_new);
            if (res < 0) {
                E("ERROR: send_http()");
                goto ret_accept;
            }
        }
        E("%s:%u <===HTTP(*)=== %s:%u", src_ip, ntohs(tcph->source), dst_ip,
          ntohs(tcph->dest));

        goto ret_mark_repeat;
    } else if (tcp_payload_len > 0) {
        goto ret_mark_repeat;
    } else if (tcph->ack) {
        E("%s:%u ===ACK===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
          ntohs(tcph->dest));

        for (i = 0; i < g_repeat; i++) {
            res = send_http(iph->daddr, iph->saddr, tcph->dest, tcph->source,
                            tcph->ack_seq, tcph->seq);
            if (res < 0) {
                E("ERROR: send_http()");
                goto ret_accept;
            }
        }
        E("(*) %s:%u <===HTTP(*)=== %s:%u", src_ip, ntohs(tcph->source),
          dst_ip, ntohs(tcph->dest));

        goto ret_accept;
    } else {
        E("WARNING: unexpected TCP packet (ignored)");
        goto ret_accept;
    }

ret_accept:
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);

ret_mark_repeat:
    return nfq_set_verdict2(qh, pkt_id, NF_REPEAT, g_fwmark, 0, NULL);
}


int main(int argc, char *argv[])
{
    static const size_t buffsize = UINT16_MAX;

    unsigned long long tmp;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int res, fd, opt, exitcode;
    ssize_t recv_len;
    char *buff;

    exitcode = EXIT_FAILURE;

    if (!argc) {
        return EXIT_FAILURE;
    }

    while ((opt = getopt(argc, argv, "h:i:m:n:r:t:")) != -1) {
        switch (opt) {
            case 'h':
                if (strlen(optarg) > _POSIX_HOST_NAME_MAX) {
                    fprintf(stderr, "%s: hostname is too long.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_hostname = optarg;
                break;
            case 'i':
                g_iface = optarg;
                if (strlen(optarg) > IFNAMSIZ - 1) {
                    fprintf(stderr, "%s: interface name is too long.\n",
                            argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;
            case 'm':
                if (sscanf(optarg, "%llu", &tmp) != 1 || tmp > UINT16_MAX) {
                    fprintf(stderr, "%s: invalid value for -m.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_fwmark = tmp;
                break;
            case 'n':
                if (sscanf(optarg, "%llu", &tmp) != 1 || !tmp ||
                    tmp > UINT16_MAX) {
                    fprintf(stderr, "%s: invalid value for -n.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_nfqnum = tmp;
                break;
            case 'r':
                if (sscanf(optarg, "%llu", &tmp) != 1 || !tmp || tmp > 10) {
                    fprintf(stderr, "%s: invalid value for -r.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_repeat = tmp;
                break;
            case 't':
                if (sscanf(optarg, "%llu", &tmp) != 1 || !tmp ||
                    tmp > UINT8_MAX) {
                    fprintf(stderr, "%s: invalid value for -t.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ttl = tmp;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!g_hostname) {
        fprintf(stderr, "%s: option -h is required.\n", argv[0]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!g_iface) {
        fprintf(stderr, "%s: option -i is required.\n", argv[0]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    E("FakeHTTP version " VERSION);

    srand(time(NULL));

    buff = malloc(buffsize);
    if (!buff) {
        E("ERROR: malloc(): %s", strerror(errno));
        return EXIT_FAILURE;
    }

    /*
        Raw Socket
    */
    g_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_sockfd < 0) {
        E("ERROR: socket(): %s", strerror(errno));
        goto free_buff;
    }

    res = setsockopt(g_sockfd, SOL_SOCKET, SO_BINDTODEVICE, g_iface,
                     strlen(g_iface));
    if (res < 0) {
        E("ERROR: setsockopt(): %s", strerror(errno));
        goto close_socket;
    }

    opt = 1;
    res = setsockopt(g_sockfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): %s", strerror(errno));
        goto close_socket;
    }

    res = setsockopt(g_sockfd, SOL_SOCKET, SO_MARK, &g_fwmark,
                     sizeof(g_fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): %s", strerror(errno));
        goto close_socket;
    }

    /*
        Netfilter Queue
    */
    h = nfq_open();
    if (!h) {
        E("ERROR: nfq_open()");
        goto close_socket;
    }

    res = nfq_unbind_pf(h, AF_INET);
    if (res < 0) {
        E("ERROR: nfq_unbind_pf()");
        goto close_nfq;
    }

    res = nfq_bind_pf(h, AF_INET);
    if (res < 0) {
        E("ERROR: nfq_bind_pf()");
        goto close_nfq;
    }

    qh = nfq_create_queue(h, g_nfqnum, &callback, NULL);
    if (!qh) {
        E("ERROR: nfq_create_queue()");
        goto close_nfq;
    }

    res = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    if (res < 0) {
        E("ERROR: nfq_set_mode()");
        goto destroy_queue;
    }

    fd = nfq_fd(h);

    /*
        Iptables
    */
    ipt_rules_cleanup();
    res = ipt_rules_setup();
    if (res) {
        E("ERROR: ipt_rules_setup()");
        goto cleanup_iptables;
    }

    /*
        Signals
    */
    res = signal_setup();
    if (res) {
        E("ERROR: signal_setup()");
        goto cleanup_iptables;
    }

    /*
        Main Loop
    */
    while (!g_exit) {
        recv_len = recv(fd, buff, buffsize, 0);
        if (recv_len < 0) {
            if (errno == EINTR) {
                g_exit = 1;
                goto exit_success;
            }
            E("ERROR: recv(): %s", strerror(errno));
            goto cleanup_iptables;
        }
        res = nfq_handle_packet(h, buff, recv_len);
        if (res < 0) {
            E("ERROR: nfq_handle_packet()");
            continue;
        }
    }

exit_success:
    E("exiting normally...");
    exitcode = EXIT_SUCCESS;

cleanup_iptables:
    ipt_rules_cleanup();

destroy_queue:
    nfq_destroy_queue(qh);

close_nfq:
    nfq_close(h);

close_socket:
    close(g_sockfd);

free_buff:
    free(buff);

    return exitcode;
}
