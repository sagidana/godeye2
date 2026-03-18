"""Scapy sniff wrapper and packet-to-dict extraction."""

import socket
import threading
import time
from datetime import datetime
from typing import Optional


def get_local_ips() -> set:
    """Collect all local IPs from all network interfaces."""
    ips = {'127.0.0.1', '::1'}
    try:
        from scapy.all import conf as scapy_conf
        for iface in scapy_conf.ifaces.values():
            if getattr(iface, 'ip', None):
                ips.add(iface.ip)
            for ip in getattr(iface, 'ips', []):
                ips.add(str(ip))
    except Exception:
        pass
    # Also read IPv6 addresses from /proc/net/if_inet6
    try:
        with open('/proc/net/if_inet6') as f:
            for line in f:
                parts = line.split()
                if parts:
                    hex_addr = parts[0]
                    groups = [hex_addr[i:i+4] for i in range(0, 32, 4)]
                    addr = socket.inet_ntop(
                        socket.AF_INET6,
                        socket.inet_pton(socket.AF_INET6, ':'.join(groups)),
                    )
                    ips.add(addr)
    except Exception:
        pass
    return ips


class LocalIPRefresher:
    """Keeps local IP set fresh in a background thread."""

    def __init__(self, interval: float = 30.0):
        self._interval = interval
        self._lock = threading.Lock()
        self._ips = get_local_ips()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while True:
            time.sleep(self._interval)
            try:
                new_ips = get_local_ips()
                with self._lock:
                    self._ips = new_ips
            except Exception:
                pass

    @property
    def ips(self) -> set:
        with self._lock:
            return set(self._ips)


_TCP_PORTS: dict[int, str] = {
    21:   'ftp',
    22:   'ssh',
    25:   'smtp',
    53:   'dns',
    80:   'http',
    110:  'pop3',
    143:  'imap',
    443:  'https',
    465:  'smtps',
    587:  'smtp',
    993:  'imaps',
    995:  'pop3s',
    3306: 'mysql',
    5432: 'postgres',
    6379: 'redis',
    8080: 'http',
    8443: 'https',
}

_UDP_PORTS: dict[int, str] = {
    53:  'dns',
    67:  'dhcp',
    68:  'dhcp',
    123: 'ntp',
    161: 'snmp',
    500: 'ike',
    4500: 'ike-nat',
    5353: 'mdns',
}


def _app_protocol(transport: str, sport: int, dport: int, pkt) -> str:
    """Return the best application-layer protocol name for a packet."""
    # Scapy layer detection first (most reliable)
    if pkt is not None:
        try:
            from scapy.layers.dns import DNS
            if pkt.haslayer(DNS):
                return 'dns'
        except ImportError:
            pass

    table = _TCP_PORTS if transport == 'tcp' else _UDP_PORTS
    return table.get(dport) or table.get(sport) or transport


def extract_packet_info(pkt, process_mapper, dns_tracker, local_ips: set) -> Optional[dict]:
    """
    Extract structured info from a scapy packet.
    Returns None for non-IP traffic.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    try:
        from scapy.layers.inet6 import IPv6
        has_ipv6 = True
    except ImportError:
        has_ipv6 = False

    # Feed to DNS tracker regardless
    dns_tracker.process_packet(pkt)

    # Determine IP layer
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif has_ipv6 and pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        return None

    # Determine protocol and ports
    src_port = 0
    dst_port = 0
    # IPv4 uses .proto; IPv6 uses .nh (next header)
    proto = getattr(ip_layer, 'proto', None)
    if proto is None:
        proto = getattr(ip_layer, 'nh', 0)

    _PROTO_NAMES = {1: 'icmp', 58: 'icmpv6', 2: 'igmp', 89: 'ospf', 132: 'sctp'}

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        protocol = _app_protocol('tcp', src_port, dst_port, pkt)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        protocol = _app_protocol('udp', src_port, dst_port, pkt)
    elif pkt.haslayer(ICMP):
        protocol = 'icmp'
    else:
        protocol = _PROTO_NAMES.get(proto, str(proto))

    # Determine local/remote orientation
    if src_ip in local_ips:
        local_ip, local_port = src_ip, src_port
        remote_ip, remote_port = dst_ip, dst_port
    elif dst_ip in local_ips:
        local_ip, local_port = dst_ip, dst_port
        remote_ip, remote_port = src_ip, src_port
    else:
        # Forwarded / neither end local — treat src as local
        local_ip, local_port = src_ip, src_port
        remote_ip, remote_port = dst_ip, dst_port

    # Resolve domains
    local_domain = dns_tracker.lookup(local_ip) or ''
    domain = dns_tracker.lookup(remote_ip) or ''

    src_host = dns_tracker.lookup(src_ip) or src_ip
    dst_host = dns_tracker.lookup(dst_ip) or dst_ip

    # Process lookup
    pid, comm, cmdline = process_mapper.lookup(protocol, local_ip, local_port, remote_ip, remote_port)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    return {
        'timestamp':     timestamp,
        'protocol':      protocol,
        'local_ip':      local_ip,
        'local_port':    str(local_port),
        'local_domain':  local_domain,
        'remote_ip':     remote_ip,
        'remote_port':   str(remote_port),
        'domain':        domain,
        'src_host':      src_host,
        'src_port':      str(src_port),
        'dst_host':      dst_host,
        'dst_port':      str(dst_port),
        'process':       comm,
        'cmdline':       cmdline,
        'pid':           pid,
        'length':        len(pkt),
    }
