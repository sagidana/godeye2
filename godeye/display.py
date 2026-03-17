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


def print_packet(pkt: dict, suppressed: bool = False) -> None:
    """Print a packet as a single line."""
    proto = pkt['protocol'].upper()
    proto_colour = _proto_colour(pkt['protocol'])

    local_host  = pkt['local_domain']  or pkt['local_ip']
    remote_host = pkt['remote_domain'] or pkt['remote_ip']
    local_addr  = f"{local_host}:{pkt['local_port']}"
    remote_addr = f"{remote_host}:{pkt['remote_port']}"

    pid = pkt['pid']
    process = pkt['process']
    process_display = f"{process} (pid: {pid})" if pid != -1 else process

    line = Text()
    line.append(f"[{pkt['timestamp']}] ", style='dim white')
    line.append(f"{proto:<6}", style=proto_colour)
    line.append(f"{local_addr}", style='white')
    line.append(' → ', style='')
    line.append(f"{remote_addr}", style='white')
    line.append(f"  {process_display}", style='green')
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
