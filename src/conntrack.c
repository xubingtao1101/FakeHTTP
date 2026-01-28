/*
 * conntrack.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "conntrack.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "logging.h"
#include "globvar.h"

#define CAPACITY           1000
#define CONNECTION_TIMEOUT 300 /* 5 分钟超时 */

struct connection {
    int initialized;
    struct sockaddr_storage saddr;
    struct sockaddr_storage daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t packet_count;
    time_t last_seen;
};

static struct connection *conns = NULL;
static size_t conns_count = 0;

static int same_addr(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *addr_in_1, *addr_in_2;
    struct sockaddr_in6 *addr_in6_1, *addr_in6_2;

    if (addr1->sa_family != addr2->sa_family) {
        return 0;
    }

    if (addr1->sa_family == AF_INET) {
        addr_in_1 = (struct sockaddr_in *) addr1;
        addr_in_2 = (struct sockaddr_in *) addr2;
        return addr_in_1->sin_addr.s_addr == addr_in_2->sin_addr.s_addr;
    } else if (addr1->sa_family == AF_INET6) {
        addr_in6_1 = (struct sockaddr_in6 *) addr1;
        addr_in6_2 = (struct sockaddr_in6 *) addr2;
        return memcmp(&addr_in6_1->sin6_addr, &addr_in6_2->sin6_addr,
                      sizeof(addr_in6_1->sin6_addr)) == 0;
    }
    return 0;
}

static int same_connection(struct connection *conn, struct sockaddr *saddr,
                           struct sockaddr *daddr, uint16_t sport,
                           uint16_t dport)
{
    if (!conn->initialized) {
        return 0;
    }

    if (conn->sport != sport || conn->dport != dport) {
        return 0;
    }

    if (!same_addr((struct sockaddr *) &conn->saddr, saddr)) {
        return 0;
    }

    if (!same_addr((struct sockaddr *) &conn->daddr, daddr)) {
        return 0;
    }

    return 1;
}

static struct connection *find_connection(struct sockaddr *saddr,
                                          struct sockaddr *daddr,
                                          uint16_t sport, uint16_t dport)
{
    size_t i;

    for (i = 0; i < conns_count; i++) {
        if (same_connection(&conns[i], saddr, daddr, sport, dport)) {
            return &conns[i];
        }
    }

    return NULL;
}

static struct connection *find_or_create_connection(struct sockaddr *saddr,
                                                    struct sockaddr *daddr,
                                                    uint16_t sport,
                                                    uint16_t dport)
{
    struct connection *conn;
    time_t now;
    size_t i;

    /* 先尝试查找现有连接 */
    conn = find_connection(saddr, daddr, sport, dport);
    if (conn) {
        return conn;
    }

    /* 清理超时的连接 */
    now = time(NULL);
    for (i = 0; i < conns_count; i++) {
        if (conns[i].initialized &&
            (now - conns[i].last_seen) > CONNECTION_TIMEOUT) {
            conns[i].initialized = 0;
        }
    }

    /* 查找空闲槽位 */
    for (i = 0; i < conns_count; i++) {
        if (!conns[i].initialized) {
            conn = &conns[i];
            goto init;
        }
    }

    /* 如果数组未满，添加新连接 */
    if (conns_count < CAPACITY) {
        conn = &conns[conns_count++];
        goto init;
    }

    /* 数组已满，使用 LRU：找到最久未使用的连接 */
    conn = &conns[0];
    for (i = 1; i < conns_count; i++) {
        if (conns[i].last_seen < conn->last_seen) {
            conn = &conns[i];
        }
    }

init:
    memset(conn, 0, sizeof(*conn));
    conn->initialized = 1;

    if (saddr->sa_family == AF_INET) {
        memcpy(&conn->saddr, saddr, sizeof(struct sockaddr_in));
        memcpy(&conn->daddr, daddr, sizeof(struct sockaddr_in));
    } else if (saddr->sa_family == AF_INET6) {
        memcpy(&conn->saddr, saddr, sizeof(struct sockaddr_in6));
        memcpy(&conn->daddr, daddr, sizeof(struct sockaddr_in6));
    } else {
        return NULL;
    }

    conn->sport = sport;
    conn->dport = dport;
    conn->packet_count = 0;
    conn->last_seen = time(NULL);

    return conn;
}

int fh_conntrack_setup(void)
{
    conns = calloc(CAPACITY, sizeof(*conns));
    if (!conns) {
        E("ERROR: calloc(): %s", strerror(errno));
        return -1;
    }
    conns_count = 0;

    return 0;
}

void fh_conntrack_cleanup(void)
{
    free(conns);
    conns = NULL;
    conns_count = 0;
}

int fh_conntrack_increment(struct sockaddr *saddr, struct sockaddr *daddr,
                           uint16_t sport, uint16_t dport)
{
    struct connection *conn;

    if (!conns) {
        return -1;
    }

    conn = find_or_create_connection(saddr, daddr, sport, dport);
    if (!conn) {
        return -1;
    }

    conn->packet_count++;
    conn->last_seen = time(NULL);

    if (conn->packet_count >= g_ctx.packet_threshold) {
        conn->packet_count = 0; /* 重置计数 */
        return 1;               /* 达到阈值 */
    }

    return 0; /* 未达到阈值 */
}

void fh_conntrack_remove(struct sockaddr *saddr, struct sockaddr *daddr,
                         uint16_t sport, uint16_t dport)
{
    struct connection *conn;

    if (!conns) {
        return;
    }

    conn = find_connection(saddr, daddr, sport, dport);
    if (conn) {
        conn->initialized = 0;
    }
}
