"""godeye entry point — CLI arg parsing and main sniff loop."""

import argparse
import logging
import os
import sys
from pathlib import Path


def _check_privileges() -> None:
    """Exit with error if not running as root or without CAP_NET_RAW."""
    if os.geteuid() == 0:
        return
    # Check for CAP_NET_RAW via /proc/self/status
    try:
        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('CapEff:'):
                    cap_eff = int(line.split()[1], 16)
                    # CAP_NET_RAW = bit 13
                    if cap_eff & (1 << 13):
                        return
    except OSError:
        pass
    print(
        '[godeye] Error: must run as root or with CAP_NET_RAW capability.\n'
        '  Try: sudo godeye',
        file=sys.stderr,
    )
    sys.exit(1)


def _read_dns_servers() -> list[str]:
    """Parse nameserver lines from /etc/resolv.conf."""
    servers = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def _real_home() -> Path:
    """Return the invoking user's home dir, even when running under sudo."""
    import pwd
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def main():
    parser = argparse.ArgumentParser(
        prog='godeye',
        description='Network traffic monitor — shows unmatched packets in real time.',
    )
    parser.add_argument('-i', '--interface', metavar='INTERFACE', default=None,
                        help='Network interface to capture on (default: all)')
    parser.add_argument('-c', '--config', metavar='CONFIG', default=None,
                        help='Path to rules.json (default: ~/.config/godeye/rules.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Also show suppressed/matched packets (dimmed)')
    args = parser.parse_args()

    _check_privileges()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='[godeye dbg] %(name)s: %(message)s',
    )

    config_path = args.config or str(_real_home() / '.config' / 'godeye' / 'rules.json')

    # Lazy imports after privilege check so error messages are clean
    from godeye.capture import LocalIPRefresher, extract_packet_info
    from godeye.display import print_banner, print_packet
    from godeye.dns_tracker import DNSTracker
    from godeye.potential_rules import POTENTIAL_RULES_PATH, record_potential_rule
    from godeye.process_mapper import ProcessMapper
    from godeye.rules import RuleEngine

    try:
        open(POTENTIAL_RULES_PATH, 'w').close()
    except OSError:
        pass

    rules = RuleEngine(config_path)
    process_mapper = ProcessMapper()
    dns_tracker = DNSTracker()
    ip_refresher = LocalIPRefresher()

    from scapy.all import get_if_list
    if args.interface:
        ifaces = [args.interface]
    else:
        ifaces = get_if_list()

    print_banner(ifaces, config_path, rules.rule_count, _read_dns_servers())

    def handle_packet(pkt):
        try:
            info = extract_packet_info(pkt, process_mapper, dns_tracker, ip_refresher.ips)
        except Exception:
            return
        if info is None:
            return
        if rules.is_suppressed(info):
            return
        print_packet(info, suppressed=False)
        record_potential_rule(info)

    try:
        from scapy.all import sniff
        sniff(
            iface=ifaces,
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print('\n[godeye] Stopped.', file=sys.stderr)
        sys.exit(0)
    except PermissionError as e:
        print(f'[godeye] Permission error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
