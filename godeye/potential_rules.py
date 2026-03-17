"""Suggest and persist potential suppression rules for unmatched packets."""

import json
import re
import threading

POTENTIAL_RULES_PATH = '/tmp/godeye.potential_rules'

_lock = threading.Lock()


def _base_domain(domain: str) -> str:
    """Return the registrable domain (last two labels) from a FQDN.

    'www.example.com' -> 'example.com'
    'example.com'     -> 'example.com'
    'a.b.example.com' -> 'example.com'
    """
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def suggest_rule(pkt: dict) -> dict:
    """Build the most general suppression rule for an unmatched packet.

    Field priority (highest to lowest):
      1. process (comm name)
      2. remote_domain  — collapsed to base domain
      3. protocol       — fallback when no remote_domain
      4. local_ip       — last resort when nothing else is available
    """
    rule: dict = {}

    # 1. Process / comm
    comm = pkt.get('process', '')
    if comm and comm not in ('', '-'):
        rule['process'] = re.escape(comm)

    # 2. Remote domain
    remote_domain = pkt.get('remote_domain', '')
    if remote_domain:
        base = _base_domain(remote_domain)
        # Match bare domain or any subdomain: example.com, sub.example.com, …
        rule['remote_domain'] = r'(^|\.)' + re.escape(base) + r'$'
    else:
        # 3. Protocol as next best identifier
        protocol = pkt.get('protocol', '')
        if protocol:
            rule['protocol'] = re.escape(protocol)

        # 4. local_ip only when nothing more specific is available
        if not rule:
            local_ip = pkt.get('local_ip', '')
            if local_ip:
                rule['local_ip'] = re.escape(local_ip)

    return rule


def _load_rules(path: str) -> list[dict]:
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError):
        return []


def _save_rules(path: str, rules: list[dict]) -> None:
    with open(path, 'w') as f:
        for rule in rules:
            f.write(json.dumps(rule, ensure_ascii=False) + '\n')


def record_potential_rule(pkt: dict, path: str = POTENTIAL_RULES_PATH) -> None:
    """Append a suggested rule for *pkt* to *path*.

    Deduplication with LRU ordering:
    - If an identical rule already exists it is removed from its current
      position and re-appended at the end (most-recently-seen last).
    - New rules are simply appended.
    - No-op when the generated rule is empty (would match everything).
    """
    rule = suggest_rule(pkt)
    if not rule:
        return

    with _lock:
        rules = _load_rules(path)
        rules = [r for r in rules if r != rule]   # remove duplicate if present
        rules.append(rule)                         # (re-)append at tail
        _save_rules(path, rules)
