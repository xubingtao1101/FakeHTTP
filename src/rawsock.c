/*
 * rawsock.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "rawsock.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>

#include "globvar.h"
#include "logging.h"

int fh_rawsock_setup(void)
{
    int res, opt, sock_fd;
    const char *err_hint;

    sock_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (sock_fd < 0) {
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

    res = setsockopt(sock_fd, SOL_SOCKET, SO_MARK, &g_ctx.fwmark,
                     sizeof(g_ctx.fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_MARK: %s", strerror(errno));
        goto close_socket;
    }

    opt = 7;
    res = setsockopt(sock_fd, SOL_SOCKET, SO_PRIORITY, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    /*
        Set SO_RCVBUF to the minimum, since we never call recvfrom() on this
        socket.
    */
    opt = 128;
    res = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    g_ctx.sockfd = sock_fd;

    return 0;

close_socket:
    close(sock_fd);

    return -1;
}


void fh_rawsock_cleanup(void)
{
    if (g_ctx.sockfd >= 0) {
        close(g_ctx.sockfd);
        g_ctx.sockfd = -1;
    }
}
