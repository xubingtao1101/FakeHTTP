/*
 * mainfun.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "mainfun.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include "globvar.h"
#include "logging.h"
#include "nfqueue.h"
#include "nfrules.h"
#include "process.h"
#include "rawsock.h"
#include "signals.h"

#ifndef VERSION
#define VERSION "dev"
#endif /* VERSION */

static void print_usage(const char *name)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  -d                 run as a daemon\n"
            "  -f                 skip firewall rules\n"
            "  -h <hostname>      hostname for obfuscation (required)\n"
            "  -i <interface>     network interface name (required)\n"
            "  -k                 kill the running process\n"
            "  -m <mark>          fwmark for bypassing the queue\n"
            "  -n <number>        netfilter queue number\n"
            "  -r <repeat>        duplicate generated packets for <repeat> "
            "times\n"
            "  -s                 enable silent mode\n"
            "  -t <ttl>           TTL for generated packets\n"
            "  -w <file>          write log to <file> instead of stderr\n"
            "  -x <mask>          set the mask for fwmark\n"
            "  -z                 use iptables commands instead of nft\n"
            "\n"
            "FakeHTTP version " VERSION "\n",
            name);
}


int main(int argc, char *argv[])
{
    unsigned long long tmp;
    int res, opt, exitcode;

    if (!argc || !argv[0]) {
        return EXIT_FAILURE;
    }

    exitcode = EXIT_FAILURE;

    while ((opt = getopt(argc, argv, "dfh:i:km:n:r:st:w:x:z")) != -1) {
        switch (opt) {
            case 'd':
                g_ctx.daemon = 1;
                break;

            case 'f':
                g_ctx.skipfw = 1;
                break;

            case 'h':
                if (strlen(optarg) > _POSIX_HOST_NAME_MAX) {
                    fprintf(stderr, "%s: hostname is too long.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.hostname = optarg;
                break;

            case 'i':
                g_ctx.iface = optarg;
                if (strlen(optarg) > IFNAMSIZ - 1) {
                    fprintf(stderr, "%s: interface name is too long.\n",
                            argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;

            case 'k':
                g_ctx.killproc = 1;
                break;

            case 'm':
                tmp = strtoull(optarg, NULL, 0);
                if (!tmp || tmp > UINT32_MAX) {
                    fprintf(stderr, "%s: invalid value for -m.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.fwmark = tmp;
                break;

            case 'n':
                tmp = strtoull(optarg, NULL, 0);
                if (!tmp || tmp > UINT32_MAX) {
                    fprintf(stderr, "%s: invalid value for -n.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.nfqnum = tmp;
                break;

            case 'r':
                tmp = strtoull(optarg, NULL, 0);
                if (!tmp || tmp > 10) {
                    fprintf(stderr, "%s: invalid value for -r.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.repeat = tmp;
                break;

            case 's':
                g_ctx.silent = 1;
                break;

            case 't':
                tmp = strtoull(optarg, NULL, 0);
                if (!tmp || tmp > UINT8_MAX) {
                    fprintf(stderr, "%s: invalid value for -t.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.ttl = tmp;
                break;

            case 'w':
                g_ctx.logpath = optarg;
                if (strlen(g_ctx.logpath) > PATH_MAX - 1) {
                    fprintf(stderr, "%s: path of log file is too long.\n",
                            argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;

            case 'x':
                tmp = strtoull(optarg, NULL, 0);
                if (!tmp || tmp > UINT32_MAX) {
                    fprintf(stderr, "%s: invalid value for -x.\n", argv[0]);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                g_ctx.fwmask = tmp;
                break;

            case 'z':
                g_ctx.use_iptables = 1;
                break;

            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (g_ctx.killproc) {
        res = fh_logger_setup();
        if (res < 0) {
            EE(T(fh_logger_setup));
            return EXIT_FAILURE;
        }
        res = fh_kill_running(SIGTERM);
        fh_logger_cleanup();

        return res < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    if (!g_ctx.fwmask) {
        g_ctx.fwmask = g_ctx.fwmark;
    } else if ((g_ctx.fwmark & g_ctx.fwmask) != g_ctx.fwmark) {
        fprintf(stderr, "%s: invalid value for -m/-x.\n", argv[0]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!g_ctx.hostname) {
        fprintf(stderr, "%s: option -h is required.\n", argv[0]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!g_ctx.iface) {
        fprintf(stderr, "%s: option -i is required.\n", argv[0]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (g_ctx.daemon) {
        res = daemon(0, 0);
        if (res < 0) {
            fprintf(stderr, "%s: failed to daemonize: %s\n", argv[0],
                    strerror(errno));
            return EXIT_FAILURE;
        }

        if (g_ctx.logfp == stderr) {
            g_ctx.silent = 1;
        }
    }

    srand(time(NULL));

    res = fh_logger_setup();
    if (res < 0) {
        EE(T(fh_logger_setup));
        return EXIT_FAILURE;
    }

    E("FakeHTTP version " VERSION);
    E("");
    E("FakeHTTP is free software licensed under the GPLv3.");
    E("Distribution without the accompanying source code is not permitted.");
    E("");
    E("Home page: https://github.com/MikeWang000000/FakeHTTP");
    E("");

    res = fh_rawsock_setup(AF_INET);
    if (res < 0) {
        EE(T(fh_rawsock_setup));
        goto cleanup_logger;
    }

    res = fh_rawsock_setup(AF_INET6);
    if (res < 0) {
        EE(T(fh_rawsock_setup));
        goto cleanup_logger;
    }

    res = fh_nfq_setup();
    if (res < 0) {
        EE(T(fh_nfq_setup));
        goto cleanup_rawsock;
    }

    res = fh_nfrules_setup();
    if (res < 0) {
        EE(T(fh_nfrules_setup));
        goto cleanup_nfq;
    }

    res = fh_signal_setup();
    if (res < 0) {
        EE(T(fh_signal_setup));
        goto cleanup_nfrules;
    }

    res = setpriority(PRIO_PROCESS, getpid(), -20);
    if (res < 0) {
        EE("WARNING: setpriority(): %s", strerror(errno));
    }

    E("listening on %s, netfilter queue number %" PRIu32 "...", g_ctx.iface,
      g_ctx.nfqnum);

    /*
        Main Loop
    */
    res = fh_nfq_loop();
    if (res < 0) {
        EE(T(fh_nfq_loop));
        goto cleanup_nfrules;
    }

    E("exiting normally...");
    exitcode = EXIT_SUCCESS;

cleanup_nfrules:
    fh_nfrules_cleanup();

cleanup_nfq:
    fh_nfq_cleanup();

cleanup_rawsock:
    fh_rawsock_cleanup();

cleanup_logger:
    fh_logger_cleanup();

    return exitcode;
}
