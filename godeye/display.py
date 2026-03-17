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
    """Print a packet to the terminal. Dimmed if suppressed."""
    dim = suppressed

    proto = pkt['protocol'].upper()
    proto_colour = _proto_colour(pkt['protocol'])

    local_dom = pkt['local_domain']
    remote_dom = pkt['remote_domain']

    local_addr = f"{local_dom or pkt['local_ip']}:{pkt['local_port']}"
    remote_addr = f"{remote_dom or pkt['remote_ip']}:{pkt['remote_port']}"

    local_detail = f" ({local_dom})" if local_dom else ''
    remote_detail = f" ({remote_dom})" if remote_dom else ''

    pid = pkt['pid']
    process_str = pkt['process']
    if pid != -1:
        process_display = f"{process_str} (pid: {pid})"
    else:
        process_display = process_str

    sep = '─' * 60

    def t(text: str, style: str = '') -> Text:
        s = Text(text, style=f'dim {style}'.strip() if dim else style)
        return s

    console.print(t(sep, 'dim'))

    # Header line
    line = Text()
    line.append(f"[{pkt['timestamp']}] ", style='dim' if dim else 'dim white')
    line.append(f"{proto}  ", style=f"dim {proto_colour}" if dim else proto_colour)
    line.append(local_addr, style='dim white' if dim else 'white')
    line.append(' → ', style='dim' if dim else '')
    line.append(remote_addr, style='dim white' if dim else 'white')
    if suppressed:
        line.append('  [suppressed]', style='dim')
    console.print(line)

    indent = '  '
    console.print(
        Text(f"{indent}Process : ", style='dim' if dim else '') +
        Text(process_display, style='dim green' if dim else 'green')
    )
    console.print(
        Text(f"{indent}Local   : ", style='dim' if dim else '') +
        Text(f"{pkt['local_ip']:<15}{local_detail}", style='dim white' if dim else 'white')
    )
    console.print(
        Text(f"{indent}Remote  : ", style='dim' if dim else '') +
        Text(f"{pkt['remote_ip']:<15}{remote_detail}", style='dim white' if dim else 'white')
    )
    console.print(
        Text(f"{indent}Bytes   : ", style='dim' if dim else '') +
        Text(str(pkt['length']), style='dim' if dim else '')
    )
    console.print(t(sep, 'dim'))


def print_banner(ifaces: list[str], config_path: str, rule_count: int, dns_servers: list[str]) -> None:
    """Print startup banner."""
    console.print()
    console.print('[bold cyan]godeye[/bold cyan] — network traffic monitor', style='bold')
    console.print(f'  Interfaces: [cyan]{", ".join(ifaces)}[/cyan]')
    console.print(f'  Config    : [cyan]{config_path}[/cyan]')
    console.print(f'  Rules     : [cyan]{rule_count}[/cyan] loaded')
    if dns_servers:
        console.print(f'  DNS       : [cyan]{", ".join(dns_servers)}[/cyan]')
    console.print()
