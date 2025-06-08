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
#include <sys/socket.h>

#include "globvar.h"
#include "logging.h"

int fh_rawsock_setup(int af)
{
    int res, opt, sock_fd;
    const char *err_hint;

    sock_fd = socket(af, SOCK_RAW, IPPROTO_RAW);
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

    res = setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, g_ctx.iface,
                     strlen(g_ctx.iface));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_BINDTODEVICE: %s", strerror(errno));
        goto close_socket;
    }

    if (af == AF_INET6) {
        opt = 1;
        res = setsockopt(sock_fd, IPPROTO_IPV6, IPV6_HDRINCL, &opt,
                         sizeof(opt));
        if (res < 0) {
            E("ERROR: setsockopt(): IPV6_HDRINCL: %s", strerror(errno));
            goto close_socket;
        }
    } else {
        opt = 1;
        res = setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
        if (res < 0) {
            E("ERROR: setsockopt(): IP_HDRINCL: %s", strerror(errno));
            goto close_socket;
        }
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

    if (af == AF_INET6) {
        g_ctx.sock6fd = sock_fd;
    } else {
        g_ctx.sock4fd = sock_fd;
    }

    return 0;

close_socket:
    close(sock_fd);

    return -1;
}


void fh_rawsock_cleanup(void)
{
    if (g_ctx.sock4fd >= 0) {
        close(g_ctx.sock4fd);
        g_ctx.sock4fd = -1;
    }

    if (g_ctx.sock6fd >= 0) {
        close(g_ctx.sock6fd);
        g_ctx.sock6fd = -1;
    }
}
