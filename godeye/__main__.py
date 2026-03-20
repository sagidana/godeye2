"""godeye entry point — CLI arg parsing and main sniff loop."""

import argparse
import logging
import os
import sys
from pathlib import Path

# File logger for main — appends to the same /tmp/godeye.log used by notify.py
_log = logging.getLogger('godeye.main')
if not _log.handlers:
    _fh = logging.FileHandler('/tmp/godeye.log')
    _fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [main] %(message)s'))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)
    _log.propagate = False


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


def _do_init():
    import shutil
    import pathlib
    import subprocess
    import sysconfig

    if os.geteuid() != 0:
        print("Error: 'godeye init' must be run as root.", file=sys.stderr)
        print("  Try: sudo $(which godeye) init", file=sys.stderr)
        sys.exit(1)

    # ── 1. /usr/bin/godeye symlink ────────────────────────────────────────────
    binary = shutil.which('godeye') or str(pathlib.Path(sys.argv[0]).resolve())
    target = pathlib.Path('/usr/bin/godeye')

    if target.is_symlink():
        current = target.resolve()
        if str(current) == str(pathlib.Path(binary).resolve()):
            print(f"[init] Already set up: {target} -> {binary}")
        else:
            print(f"[init] Removing existing symlink: {target} -> {current}")
            target.unlink()
            target.symlink_to(binary)
            print(f"[init] Created: {target} -> {binary}")
    elif target.exists():
        print(f"Error: {target} exists and is not a symlink. Remove it manually.", file=sys.stderr)
        sys.exit(1)
    else:
        target.symlink_to(binary)
        print(f"[init] Created: {target} -> {binary}")

    # ── 2. bcc (BPF Compiler Collection Python bindings) ─────────────────────
    try:
        import bcc  # noqa: F401
        print("[init] bcc already importable — nothing to do.")
        print("\n[init] Done. You can now run: sudo godeye")
        return
    except ImportError:
        pass

    # Detect system package manager and install python-bcc
    PKG_MANAGERS = [
        ('pacman',  ['pacman', '-S', '--noconfirm', 'python-bcc']),
        ('apt-get', ['apt-get', 'install', '-y', 'python3-bcc']),
        ('dnf',     ['dnf',     'install', '-y', 'python3-bcc']),
        ('zypper',  ['zypper',  'install', '-y', 'python3-bcc']),
    ]

    installed = False
    for mgr_name, cmd in PKG_MANAGERS:
        if shutil.which(mgr_name):
            print(f"[init] Installing bcc via {mgr_name}...")
            result = subprocess.run(cmd)
            if result.returncode != 0:
                print(f"Error: {mgr_name} install failed (exit {result.returncode}).", file=sys.stderr)
                sys.exit(1)
            installed = True
            break

    if not installed:
        print("Error: no supported package manager found (pacman/apt-get/dnf/zypper).", file=sys.stderr)
        print("  Install python3-bcc manually, then re-run: sudo godeye init", file=sys.stderr)
        sys.exit(1)

    # Find where the system python3 put bcc (avoids pyenv intercepting 'python3')
    result = subprocess.run(
        ['/usr/bin/python3', '-c', 'import bcc, os; print(os.path.dirname(bcc.__file__))'],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        print("Error: bcc was installed but can't be located via /usr/bin/python3.", file=sys.stderr)
        print("  Try symlinking it manually into your pyenv site-packages.", file=sys.stderr)
        sys.exit(1)

    system_bcc = pathlib.Path(result.stdout.strip())

    # Symlink into the currently-running Python's site-packages
    our_site = pathlib.Path(sysconfig.get_paths()['purelib'])
    link = our_site / 'bcc'

    if link.is_symlink():
        if link.resolve() == system_bcc.resolve():
            print(f"[init] bcc symlink already correct: {link} -> {system_bcc}")
        else:
            print(f"[init] Updating bcc symlink: {link} -> {system_bcc}")
            link.unlink()
            link.symlink_to(system_bcc)
    elif link.exists():
        print(f"Error: {link} exists and is not a symlink. Remove it manually.", file=sys.stderr)
        sys.exit(1)
    else:
        link.symlink_to(system_bcc)
        print(f"[init] Linked: {link} -> {system_bcc}")

    print("\n[init] Done. You can now run: sudo godeye")


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
    parser.add_argument('--notify', action='store_true',
                        help='Show unfiltered packets as desktop OSD notifications (notify-send or osd_cat)')
    parser.add_argument(
        'action', nargs='?', default=None, choices=['init'],
        help='init: create /usr/bin/godeye symlink so sudo godeye works across all contexts'
    )
    args = parser.parse_args()

    if args.action == 'init':
        _do_init()
        return

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
    from godeye.process_mapper import create_process_mapper
    from godeye.rules import RuleEngine

    notifier = None
    if args.notify:
        _log.info('--notify flag set; initialising Notifier  euid=%d  SUDO_USER=%s',
                  os.geteuid(), os.environ.get('SUDO_USER'))
        from godeye.notify import Notifier
        notifier = Notifier()
        if not notifier.available:
            _log.error('no notification backend found; notifier disabled')
            print('[godeye] Warning: --notify requires notify-send or osd_cat; neither found.', file=sys.stderr)
            notifier = None
        else:
            _log.info('Notifier ready')

    try:
        open(POTENTIAL_RULES_PATH, 'w').close()
    except OSError:
        pass

    rules = RuleEngine(config_path)
    process_mapper, mapper_type = create_process_mapper()
    dns_tracker = DNSTracker()
    ip_refresher = LocalIPRefresher()

    from scapy.all import get_if_list
    if args.interface:
        ifaces = [args.interface]
    else:
        import socket
        up = []
        for iface in get_if_list():
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                s.bind((iface, 0))
                s.close()
                up.append(iface)
            except OSError:
                pass
        ifaces = up

    print_banner(ifaces, config_path, rules.rule_count, _read_dns_servers(), mapper_type)

    def handle_packet(pkt):
        process_mapper.prefetch()  # launch netstat immediately at packet arrival
        try:
            info = extract_packet_info(pkt, process_mapper, dns_tracker, ip_refresher.ips)
        except Exception:
            return
        if info is None:
            return
        if rules.is_suppressed(info):
            return
        _log.debug('unfiltered packet: proto=%s process=%s remote=%s:%s',
                   info.get('protocol'), info.get('process'),
                   info.get('domain') or info.get('remote_ip'), info.get('remote_port'))
        print_packet(info, suppressed=False)
        record_potential_rule(info)
        if notifier:
            notifier.notify(info)

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
