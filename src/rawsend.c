/*
 * rawsend.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "rawsend.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "globvar.h"
#include "ipv4pkt.h"
#include "ipv6pkt.h"
#include "logging.h"
#include "payload.h"

static uint8_t *payload = NULL;
static size_t payload_len = 0;
static int sockfd = -1;

static int hop_estimate(uint8_t ttl)
{
    if (ttl <= 64) {
        return 64 - ttl;
    } else if (ttl <= 128) {
        return 128 - ttl;
    } else {
        return 255 - ttl;
    }
}

static void ipaddr_to_str(struct sockaddr *addr, char ipstr[INET6_ADDRSTRLEN])
{
    static const char invalid[] = "INVALID";

    const char *res;

    if (addr->sa_family == AF_INET) {
        res = inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                        ipstr, INET6_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    } else if (addr->sa_family == AF_INET6) {
        res = inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                        ipstr, INET6_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    }

invalid:
    memcpy(ipstr, invalid, sizeof(invalid));
}


static int send_ack(struct sockaddr_ll *sll, struct sockaddr *saddr,
                    struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                    uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be)
{
    int pkt_len;
    ssize_t nbytes;
    uint8_t pkt_buff[1600] __attribute__((aligned));

    if (daddr->sa_family == AF_INET) {
        pkt_len = fh_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 0, NULL,
                               0);
        if (pkt_len < 0) {
            E(T(fh_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        pkt_len = fh_pkt6_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 0, NULL,
                               0);
        if (pkt_len < 0) {
            E(T(fh_pkt6_make));
            return -1;
        }
    } else {
        E("ERROR: Unknown address family: %d", (int) daddr->sa_family);
        return -1;
    }

    nbytes = sendto(sockfd, pkt_buff, pkt_len, 0, (struct sockaddr *) sll,
                    sizeof(*sll));
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int send_payload(struct sockaddr_ll *sll, struct sockaddr *saddr,
                        struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                        uint16_t dport_be, uint32_t seq_be, uint32_t ackseq_be)
{
    int pkt_len;
    ssize_t nbytes;
    uint8_t pkt_buff[1600] __attribute__((aligned));

    if (daddr->sa_family == AF_INET) {
        pkt_len = fh_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 1,
                               payload, payload_len);
        if (pkt_len < 0) {
            E(T(fh_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        pkt_len = fh_pkt6_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, seq_be, ackseq_be, 1,
                               payload, payload_len);
        if (pkt_len < 0) {
            E(T(fh_pkt6_make));
            return -1;
        }
    } else {
        E("ERROR: Unknown address family: %d", (int) saddr->sa_family);
        return -1;
    }

    nbytes = sendto(sockfd, pkt_buff, pkt_len, 0, (struct sockaddr *) sll,
                    sizeof(*sll));
    if (nbytes < 0) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


int fh_rawsend_setup(void)
{
    int res, opt;
    const char *err_hint;

    sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (sockfd < 0) {
        switch (errno) {
            case EPERM:
                err_hint = " (Are you root?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: socket(): %s%s", strerror(errno), err_hint);
        return -1;
    }

    res = setsockopt(sockfd, SOL_SOCKET, SO_MARK, &g_ctx.fwmark,
                     sizeof(g_ctx.fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_MARK: %s", strerror(errno));
        goto close_socket;
    }

    opt = 7;
    res = setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    /*
        Set SO_RCVBUF to the minimum, since we never call recvfrom() on this
        socket.
    */
    opt = 128;
    res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    return 0;

close_socket:
    close(sockfd);

    return -1;
}


void fh_rawsend_cleanup(void)
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}


int fh_rawsend_handle(struct sockaddr_ll *sll, uint8_t *pkt_data, int pkt_len)
{
    uint32_t ack_new;
    uint16_t ethertype;
    int res, i, tcp_payload_len, hop;
    uint8_t src_ttl, snd_ttl;
    struct tcphdr *tcph;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    struct sockaddr_storage saddr_store, daddr_store;
    struct sockaddr *saddr, *daddr;

    saddr = (struct sockaddr *) &saddr_store;
    daddr = (struct sockaddr *) &daddr_store;

    ethertype = ntohs(sll->sll_protocol);
    if (g_ctx.use_ipv4 && ethertype == ETHERTYPE_IP) {
        res = fh_pkt4_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &tcph,
                            &tcp_payload_len);
        if (res < 0) {
            E(T(fh_pkt4_parse));
            return -1;
        }
    } else if (g_ctx.use_ipv6 && ethertype == ETHERTYPE_IPV6) {
        res = fh_pkt6_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &tcph,
                            &tcp_payload_len);
        if (res < 0) {
            E(T(fh_pkt6_parse));
            return -1;
        }
    } else {
        E("ERROR: unknown ethertype 0x%04x");
        return -1;
    }

    if (!g_ctx.silent) {
        ipaddr_to_str(saddr, src_ip);
        ipaddr_to_str(daddr, dst_ip);
    }

    snd_ttl = 0;

    if (!g_ctx.nohopest) {
        hop = hop_estimate(src_ttl);
        if (hop <= g_ctx.ttl) {
            E_INFO("%s:%u ===LOCAL(?)===> %s:%u", src_ip, ntohs(tcph->source),
                   dst_ip, ntohs(tcph->dest));
            return 0;
        }
        if (g_ctx.dynamic_pct) {
            snd_ttl = hop * g_ctx.dynamic_pct / 100;
        }
    }

    if (snd_ttl < g_ctx.ttl) {
        snd_ttl = g_ctx.ttl;
    }

    if (tcp_payload_len > 0) {
        E_INFO("%s:%u ===PAYLOAD(?)===> %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));
        return 0;
    } else if (tcph->syn && tcph->ack) {
        if (!g_ctx.outbound) {
            E_INFO("%s:%u ===SYN-ACK(?)===> %s:%u", src_ip,
                   ntohs(tcph->source), dst_ip, ntohs(tcph->dest));
            return 0;
        }

        E_INFO("%s:%u ===SYN-ACK===> %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        ack_new = ntohl(tcph->seq);
        ack_new++;
        ack_new = htonl(ack_new);

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_ack(sll, daddr, saddr, snd_ttl, tcph->dest,
                           tcph->source, tcph->ack_seq, ack_new);
            if (res < 0) {
                E(T(send_ack));
                return -1;
            }
        }
        E_INFO("%s:%u <===ACK(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));


        th_payload_get(&payload, &payload_len);
        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_payload(sll, daddr, saddr, snd_ttl, tcph->dest,
                               tcph->source, tcph->ack_seq, ack_new);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        return 0;
    } else if (tcph->ack) {
        if (!g_ctx.inbound) {
            E_INFO("%s:%u ===ACK(?)===> %s:%u", src_ip, ntohs(tcph->source),
                   dst_ip, ntohs(tcph->dest));
            return 0;
        }

        E_INFO("%s:%u ===ACK===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
               ntohs(tcph->dest));

        th_payload_get(&payload, &payload_len);
        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_payload(sll, daddr, saddr, snd_ttl, tcph->dest,
                               tcph->source, tcph->ack_seq, tcph->seq);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", src_ip, ntohs(tcph->source),
               dst_ip, ntohs(tcph->dest));

        return 0;
    } else {
        E_INFO("%s:%u ===(?)===> %s:%u", src_ip, ntohs(tcph->source), dst_ip,
               ntohs(tcph->dest));
        return 1;
    }
}
