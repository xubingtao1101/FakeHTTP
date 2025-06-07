/*
 * nfrules.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "nfrules.h"

#include <stdlib.h>

#include "globvar.h"
#include "ipv4ipt.h"
#include "ipv4nft.h"
#include "logging.h"
#include "process.h"

static int nft_is_working(void)
{
    char *nft_ver_cmd[] = {"nft", "--version", NULL};

    return !fh_execute_command(nft_ver_cmd, 1, NULL);
}


int fh_nfrules_setup(void)
{
    int res;

    if (!g_ctx.use_iptables && !nft_is_working()) {
        E("WARNING: Falling back to iptables command, as nft command is not "
          "working.");
        g_ctx.use_iptables = 1;
    }

    if (g_ctx.use_iptables) {
        res = fh_ipt4_flush(1);
        if (res < 0) {
            E("ERROR: fh_ipt4_flush()");
            return -1;
        }

        res = fh_ipt4_add();
        if (res < 0) {
            E("ERROR: fh_ipt4_add()");
            fh_ipt4_flush(0);
            return -1;
        }
    } else {
        res = fh_nft4_flush(1);
        if (res < 0) {
            E("ERROR: fh_nft4_flush()");
            return -1;
        }

        res = fh_nft4_add();
        if (res < 0) {
            E("ERROR: fh_nft4_add()");
            fh_nft4_flush(0);
            return -1;
        }
    }

    return 0;
}


void fh_nfrules_cleanup(void)
{
    if (g_ctx.use_iptables) {
        fh_ipt4_flush(0);
    } else {
        fh_nft4_flush(0);
    }
}
