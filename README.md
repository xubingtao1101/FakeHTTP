# FakeHTTP

Obfuscate all your TCP connections into HTTP protocol, using Netfilter Queue (NFQUEUE).

[[ 中文文档 ]](https://github.com/MikeWang000000/FakeHTTP/wiki)


## Quick Start

```
fakehttp -h www.example.com -i eth0
```


## Usage

```
Usage: fakehttp [options]

Options:
  -d                 run as a daemon
  -f                 skip firewall rules
  -h <hostname>      hostname for obfuscation (required)
  -i <interface>     network interface name (required)
  -k                 kill the running process
  -m <mark>          fwmark for bypassing the queue
  -n <number>        netfilter queue number
  -r <repeat>        duplicate generated packets for <repeat> times
  -s                 enable silent mode
  -t <ttl>           TTL for generated packets
  -w <file>          write log to <file> instead of stderr
  -x <mask>          set the mask for fwmark
  -z                 use iptables commands instead of nft

```


## License

GNU General Public License v3.0
