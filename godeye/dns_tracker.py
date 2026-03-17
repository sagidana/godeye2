"""DNS response parser → ip → domain map."""

import logging
import socket
import threading
from typing import Optional

log = logging.getLogger('godeye.dns')


class DNSTracker:
    """Tracks DNS responses to map IP addresses to domain names."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_map: dict[str, set] = {}  # ip → set of domain names

    def process_packet(self, pkt) -> None:
        """Extract A/AAAA records from DNS response packets."""
        try:
            from scapy.layers.dns import DNS
        except ImportError:
            log.debug('scapy DNS layer not available')
            return

        if not pkt.haslayer(DNS):
            return

        dns = pkt[DNS]
        log.debug('DNS packet: qr=%s ancount=%s', dns.qr, getattr(dns, 'ancount', '?'))

        if dns.qr != 1:
            log.debug('  → skipping (not a response, qr=%s)', dns.qr)
            return
        if not dns.an:
            log.debug('  → skipping (no answer section)')
            return

        with self._lock:
            rr = dns.an
            while rr is not None and hasattr(rr, 'rrname'):
                rr_type = getattr(rr, 'type', None)
                log.debug('  RR rrname=%s type=%s rdata=%s', rr.rrname, rr_type, getattr(rr, 'rdata', '?'))
                if rr_type in (1, 28):  # A=1, AAAA=28
                    try:
                        ip = _rdata_to_str(rr.rdata, rr_type)
                        name = _decode_name(rr.rrname)
                        if ip and name:
                            self._ip_map.setdefault(ip, set()).add(name)
                            log.debug('  → mapped %s → %s', ip, name)
                        else:
                            log.debug('  → skipped (ip=%r name=%r)', ip, name)
                    except Exception as e:
                        log.debug('  → error extracting RR: %s', e)
                rr = rr.payload if hasattr(rr, 'payload') else None

    def lookup(self, ip: str) -> Optional[str]:
        """Return the first known domain for an IP, or None."""
        with self._lock:
            domains = self._ip_map.get(ip)
            if domains:
                result = next(iter(domains))
                log.debug('DNS lookup %s → %s', ip, result)
                return result
        log.debug('DNS lookup %s → (not found)', ip)
        return None


def _rdata_to_str(rdata, rr_type: int) -> Optional[str]:
    """Convert scapy rdata to a plain IP string."""
    if isinstance(rdata, bytes):
        af = socket.AF_INET if rr_type == 1 else socket.AF_INET6
        try:
            return socket.inet_ntop(af, rdata)
        except OSError:
            return None
    return str(rdata)


def _decode_name(name) -> Optional[str]:
    if isinstance(name, bytes):
        return name.decode('utf-8', errors='replace').rstrip('.')
    return str(name).rstrip('.')
