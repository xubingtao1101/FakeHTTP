/*
 * ipv4ipt.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "ipv4ipt.h"

#include <inttypes.h>
#include <stdlib.h>

#include "globvar.h"
#include "logging.h"
#include "process.h"

int fh_ipt4_flush(int auto_create)
{
    int res;
    size_t i, cnt;
    char *ipt_flush_cmd[] = {"iptables", "-w",       "-t", "mangle",
                             "-F",       "FAKEHTTP", NULL};
    char *ipt_create_cmds[][32] = {
        {"iptables", "-w", "-t", "mangle", "-N", "FAKEHTTP", NULL},

        {"iptables", "-w", "-t", "mangle", "-I", "INPUT", "-j", "FAKEHTTP",
         NULL},

        {"iptables", "-w", "-t", "mangle", "-I", "FORWARD", "-j", "FAKEHTTP",
         NULL}};

    res = fh_execute_command(ipt_flush_cmd, 1, NULL);
    if (res < 0) {
        if (!auto_create) {
            return -1;
        }

        cnt = sizeof(ipt_create_cmds) / sizeof(*ipt_create_cmds);
        for (i = 0; i < cnt; i++) {
            res = fh_execute_command(ipt_create_cmds[i], 0, NULL);
            if (res < 0) {
                E("ERROR: fh_execute_command()");
                return -1;
            }
        }
    }

    return 0;
}


int fh_ipt4_add(void)
{
    char xmark_str[64], nfqnum_str[32], iface_str[32];
    size_t i, ipt_cmds_cnt, ipt_opt_cmds_cnt;
    int res;
    char *ipt_cmds[][32] = {
        /*
            exclude marked packets
        */
        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark",
         "--mark", xmark_str, "-j", "CONNMARK", "--set-xmark", xmark_str,
         NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "connmark",
         "--mark", xmark_str, "-j", "MARK", "--set-xmark", xmark_str, NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-m", "mark",
         "--mark", xmark_str, "-j", "RETURN", NULL},

        /*
            exclude local IPs
        */
        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s", "0.0.0.0/8",
         "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "10.0.0.0/8", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "100.64.0.0/10", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "127.0.0.0/8", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "169.254.0.0/16", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "172.16.0.0/12", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "192.168.0.0/16", "-j", "RETURN", NULL},

        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-s",
         "224.0.0.0/3", "-j", "RETURN", NULL},

        /*
            send to nfqueue
        */
        {"iptables", "-w", "-t", "mangle", "-A", "FAKEHTTP", "-i", iface_str,
         "-p", "tcp", "--tcp-flags", "ACK,FIN,RST", "ACK", "-j", "NFQUEUE",
         "--queue-bypass", "--queue-num", nfqnum_str, NULL}};

    char *ipt_opt_cmds[][32] = {
        /*
            exclude packets from connections with more than 32 packets
        */
        {"iptables", "-w", "-t", "mangle", "-I", "FAKEHTTP", "-m", "connbytes",
         "!", "--connbytes", "0:32", "--connbytes-dir", "both",
         "--connbytes-mode", "packets", "-j", "RETURN", NULL},

        /*
            exclude big packets
        */
        {"iptables", "-w", "-t", "mangle", "-I", "FAKEHTTP", "-m", "length",
         "!", "--length", "0:120", "-j", "RETURN", NULL}};

    ipt_cmds_cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);
    ipt_opt_cmds_cnt = sizeof(ipt_opt_cmds) / sizeof(*ipt_opt_cmds);

    res = snprintf(xmark_str, sizeof(xmark_str), "%" PRIu32 "/%" PRIu32,
                   g_ctx.fwmark, g_ctx.fwmask);
    if (res < 0 || (size_t) res >= sizeof(xmark_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    res = snprintf(nfqnum_str, sizeof(nfqnum_str), "%" PRIu32, g_ctx.nfqnum);
    if (res < 0 || (size_t) res >= sizeof(nfqnum_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    res = snprintf(iface_str, sizeof(iface_str), "%s", g_ctx.iface);
    if (res < 0 || (size_t) res >= sizeof(iface_str)) {
        E("ERROR: snprintf()");
        return -1;
    }

    for (i = 0; i < ipt_cmds_cnt; i++) {
        res = fh_execute_command(ipt_cmds[i], 0, NULL);
        if (res < 0) {
            E("ERROR: fh_execute_command()");
            return -1;
        }
    }

    for (i = 0; i < ipt_opt_cmds_cnt; i++) {
        fh_execute_command(ipt_opt_cmds[i], 1, NULL);
    }

    return 0;
}
