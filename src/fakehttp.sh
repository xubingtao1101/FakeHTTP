#!/bin/sh
#
# fakehttp.sh - FakeHTTP
#
# Copyright (C) 2025  MikeWang000000
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

set -eu

VERSION=0.9.0

PROGNAME=fakehttp
FAKEHTTPNFQ=fakehttp_nfq
CHDPID=0

OPT_REPEAT=3;
OPT_FWMARK=512;
OPT_NFQNUM=512;
OPT_TTL=3;
OPT_IFACE="";
OPT_HOSTNAME="";

print_usage()
{
    cat <<EOF >&2
Usage: $PROGNAME [options]

Options:
  -h <hostname>      hostname for obfuscation (required)
  -i <interface>     either interface name (required)
  -m <mark>          fwmark for bypassing the queue
  -n <number>        netfilter queue number
  -r <repeat>        duplicate generated packets for <repeat> times
  -t <ttl>           TTL for generated packets

FakeHTTP version $VERSION
EOF
}


find_fakehttp_nfq()
{
    FAKEHTTPNFQ_LOCAL=$(cd "$(dirname "$0")" && pwd)/$FAKEHTTPNFQ
    if [ -x "$FAKEHTTPNFQ_LOCAL" ]; then
        FAKEHTTPNFQ=$FAKEHTTPNFQ_LOCAL
    fi

    if ! which "$FAKEHTTPNFQ" >/dev/null 2>&1; then
        echo "Executable $FAKEHTTPNFQ was not found. Please check your installation." >&2
        exit 1
    fi
}


cleanup_ipt()
{
    iptables -t mangle -F FAKEHTTP
    iptables -t mangle -D PREROUTING -j FAKEHTTP
    iptables -t mangle -X FAKEHTTP

    iptables -t mangle -F FAKEHTTPMARK
    iptables -t mangle -D INPUT -j FAKEHTTPMARK
    iptables -t mangle -D FORWARD -j FAKEHTTPMARK
    iptables -t mangle -D OUTPUT -j FAKEHTTPMARK
    iptables -t mangle -X FAKEHTTPMARK
}


setup_ipt()
{
    iptables -t mangle -N FAKEHTTPMARK
    iptables -t mangle -I INPUT -j FAKEHTTPMARK
    iptables -t mangle -I FORWARD -j FAKEHTTPMARK
    iptables -t mangle -I OUTPUT -j FAKEHTTPMARK
    iptables -t mangle -A FAKEHTTPMARK -m mark --mark "$OPT_FWMARK" -j CONNMARK --save-mark

    iptables -t mangle -N FAKEHTTP
    iptables -t mangle -I PREROUTING -j FAKEHTTP
    # exclude marked packets
    iptables -t mangle -A FAKEHTTP -m connmark --mark "$OPT_FWMARK" -j CONNMARK --restore-mark
    iptables -t mangle -A FAKEHTTP -m mark --mark "$OPT_FWMARK" -j RETURN
    # exclude local IPs
    iptables -t mangle -A FAKEHTTP -s 0.0.0.0/8 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 10.0.0.0/8 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 100.64.0.0/10 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 127.0.0.0/8 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 169.254.0.0/16 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 172.16.0.0/12 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 192.168.0.0/16 -j RETURN
    iptables -t mangle -A FAKEHTTP -s 224.0.0.0/3 -j RETURN
    # send to nfqueue
    iptables -t mangle -A FAKEHTTP -i "$OPT_IFACE" -p tcp --tcp-flags ACK,FIN,RST ACK -j NFQUEUE --queue-num "$OPT_NFQNUM"
}


cleanup()
{
    if [ "$CHDPID" -ne 0 ]; then
        kill "$CHDPID"
    fi

    (set +e && cleanup_ipt || true) 2>/dev/null
}


main()
{
    cleanup
    trap 'exit 1' INT HUP QUIT TERM ALRM USR1
    trap cleanup EXIT
    find_fakehttp_nfq

    "$FAKEHTTPNFQ" -c \
        -h "$OPT_HOSTNAME" \
        -i "$OPT_IFACE" \
        -m "$OPT_FWMARK" \
        -n "$OPT_NFQNUM" \
        -r "$OPT_REPEAT" \
        -t "$OPT_TTL"

    "$FAKEHTTPNFQ" \
        -h "$OPT_HOSTNAME" \
        -i "$OPT_IFACE" \
        -m "$OPT_FWMARK" \
        -n "$OPT_NFQNUM" \
        -r "$OPT_REPEAT" \
        -t "$OPT_TTL" &

    CHDPID=$!

    setup_ipt
    wait
    CHDPID=0
}


while getopts "h:i:m:n:r:t:" opt; do
    case $opt in
        h)
            OPT_HOSTNAME=$OPTARG
            ;;
        i)
            OPT_IFACE=$OPTARG
            ;;
        m)
            OPT_FWMARK=$OPTARG
            ;;
        n)
            OPT_NFQNUM=$OPTARG
            ;;
        r)
            OPT_REPEAT=$OPTARG
            ;;
        t)
            OPT_TTL=$OPTARG
            ;;
        ?)
            print_usage
            exit 1
            ;;
    esac
done

if [ -z "$OPT_HOSTNAME" ]; then
    echo "Option -h is required." >&2
    print_usage
    exit 1
fi

if [ -z "$OPT_IFACE" ]; then
    echo "Option -i is required." >&2
    print_usage
    exit 1
fi

main
