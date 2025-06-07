/*
 * ipv4pkt.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "ipv4pkt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#include "globvar.h"

int fh_pkt4_make(char *buffer, size_t buffer_size, uint32_t saddr_be,
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
    iph->ttl = g_ctx.ttl;
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

    nfq_ip_set_checksum(iph);
    nfq_tcp_compute_checksum_ipv4(tcph, iph);

    return pkt_len;
}
