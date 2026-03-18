"""ANSI-coloured packet printer using rich."""

from rich.console import Console
from rich.text import Text

console = Console()

_PROTO_COLOURS = {
    'tcp':  'cyan',
    'udp':  'yellow',
    'icmp': 'magenta',
}


def _proto_colour(proto: str) -> str:
    return _PROTO_COLOURS.get(proto.lower(), 'white')


_GENERIC_NAMES = frozenset({'python', 'python3', 'bash', 'sh', 'zsh', 'fish',
                             'node', 'ruby', 'perl', 'java', 'dotnet'})


def _process_display(pkt: dict) -> str:
    pid     = pkt['pid']
    process = pkt['process']
    cmdline = pkt.get('cmdline', '')
    if pid != -1:
        if process in _GENERIC_NAMES and cmdline:
            brief = cmdline if len(cmdline) <= 60 else cmdline[:57] + '...'
            return brief
        return process
    if process:
        return process
    if pkt['protocol'] in ('icmp', 'icmpv6', 'igmp'):
        return 'kernel'
    return 'unknown'


def print_packet(pkt: dict, suppressed: bool = False) -> None:
    """Print a packet as a single line."""
    proto       = pkt['protocol'].upper()
    proto_colour = _proto_colour(pkt['protocol'])

    local_addr  = f"{pkt['local_ip']}:{pkt['local_port']}"
    remote_host = pkt['domain'] or pkt['remote_ip']
    remote_addr = f"{remote_host}:{pkt['remote_port']}"

    # direction: outbound (→) when src is local, inbound (←) otherwise
    direction = '→' if pkt['src_port'] == pkt['local_port'] else '←'

    # HH:MM only
    hhmm = pkt['timestamp'][11:16]

    line = Text()
    line.append(f"[{hhmm}] ", style='dim white')
    line.append(f"{proto:<8}", style=proto_colour)
    line.append(f"{local_addr}", style='white')
    line.append(f" {direction} ", style='dim white')
    line.append(f"{remote_addr}", style='white')
    line.append(f"  {_process_display(pkt)}", style='green')
    console.print(line)


def print_banner(ifaces: list[str], config_path: str, rule_count: int,
                 dns_servers: list[str], mapper_type: str = 'netstat') -> None:
    """Print startup banner."""
    console.print()
    console.print('[bold cyan]godeye[/bold cyan] — network traffic monitor', style='bold')
    console.print(f'  Interfaces: [cyan]{", ".join(ifaces)}[/cyan]')
    console.print(f'  Config    : [cyan]{config_path}[/cyan]')
    console.print(f'  Rules     : [cyan]{rule_count}[/cyan] loaded')
    if dns_servers:
        console.print(f'  DNS       : [cyan]{", ".join(dns_servers)}[/cyan]')
    mapper_colour = 'green' if mapper_type == 'eBPF' else 'yellow'
    console.print(f'  Mapper    : [{mapper_colour}]{mapper_type}[/{mapper_colour}]')
    console.print()
