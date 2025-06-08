/*
 * ipv6ipt.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "ipv6ipt.h"

#include <inttypes.h>
#include <stdlib.h>

#include "globvar.h"
#include "logging.h"
#include "process.h"

int fh_ipt6_flush(int auto_create)
{
    int res;
    size_t i, cnt;
    char *ipt_flush_cmd[] = {"ip6tables", "-w",       "-t", "mangle",
                             "-F",        "FAKEHTTP", NULL};
    char *ipt_create_cmds[][32] = {
        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKEHTTP", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-I", "INPUT", "-j", "FAKEHTTP",
         NULL},

        {"ip6tables", "-w", "-t", "mangle", "-I", "FORWARD", "-j", "FAKEHTTP",
         NULL}};

    res = fh_execute_command(ipt_flush_cmd, 1, NULL);
    if (res < 0) {
        if (!auto_create) {
            E(T(fh_execute_command));
            return -1;
        }

        cnt = sizeof(ipt_create_cmds) / sizeof(*ipt_create_cmds);
        for (i = 0; i < cnt; i++) {
            res = fh_execute_command(ipt_create_cmds[i], 0, NULL);
            if (res < 0) {
                E(T(fh_execute_command));
                return -1;
            }
        }
    }

    return 0;
}


int fh_ipt6_add(void)
{
    char xmark_str[64], nfqnum_str[32], iface_str[32];
    size_t i, ipt_cmds_cnt, ipt_opt_cmds_cnt;
    int res;
    char *ipt_cmds[][32] = {
        /*
            exclude marked packets
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark",
         "--mark", xmark_str, "-j", "CONNMARK", "--set-xmark", xmark_str,
         NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "connmark",
         "--mark", xmark_str, "-j", "MARK", "--set-xmark", xmark_str, NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark",
         "--mark", xmark_str, "-j", "RETURN", NULL},

        /*
            exclude special IPv6 addresses
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s", "::/127",
         "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "::ffff:0:0/96", "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "64:ff9b::/96", "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "64:ff9b:1::/48", "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "2002::/16", "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s", "fc00::/7",
         "-j", "RETURN", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "fe80::/10", "-j", "RETURN", NULL},

        /*
            send to nfqueue
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-i", iface_str,
         "-p", "tcp", "--tcp-flags", "ACK,FIN,RST", "ACK", "-j", "NFQUEUE",
         "--queue-bypass", "--queue-num", nfqnum_str, NULL}};

    char *ipt_opt_cmds[][32] = {
        /*
            exclude packets from connections with more than 32 packets
        */
        {"ip6tables", "-w", "-t", "mangle", "-I", "FAKEHTTP", "-m",
         "connbytes", "!", "--connbytes", "0:32", "--connbytes-dir", "both",
         "--connbytes-mode", "packets", "-j", "RETURN", NULL},

        /*
            exclude big packets
        */
        {"ip6tables", "-w", "-t", "mangle", "-I", "FAKEHTTP", "-m", "length",
         "!", "--length", "0:120", "-j", "RETURN", NULL}};

    ipt_cmds_cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);
    ipt_opt_cmds_cnt = sizeof(ipt_opt_cmds) / sizeof(*ipt_opt_cmds);

    res = snprintf(xmark_str, sizeof(xmark_str), "%" PRIu32 "/%" PRIu32,
                   g_ctx.fwmark, g_ctx.fwmask);
    if (res < 0 || (size_t) res >= sizeof(xmark_str)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    res = snprintf(nfqnum_str, sizeof(nfqnum_str), "%" PRIu32, g_ctx.nfqnum);
    if (res < 0 || (size_t) res >= sizeof(nfqnum_str)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    res = snprintf(iface_str, sizeof(iface_str), "%s", g_ctx.iface);
    if (res < 0 || (size_t) res >= sizeof(iface_str)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    for (i = 0; i < ipt_cmds_cnt; i++) {
        res = fh_execute_command(ipt_cmds[i], 0, NULL);
        if (res < 0) {
            E(T(fh_execute_command));
            return -1;
        }
    }

    for (i = 0; i < ipt_opt_cmds_cnt; i++) {
        fh_execute_command(ipt_opt_cmds[i], 1, NULL);
    }

    return 0;
}
