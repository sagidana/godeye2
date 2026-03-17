"""Load rules.json, compile regexes, and match packets."""

import json
import re
import sys
from pathlib import Path
from typing import Optional

_RULE_FIELDS = [
    'process', 'protocol', 'local_ip', 'local_port', 'local_domain',
    'remote_ip', 'remote_port', 'remote_domain',
]

_DEFAULT_PATTERN = re.compile('.*', re.IGNORECASE)


class RuleEngine:
    """Loads rules from JSON and matches packet dicts against them."""

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path.home() / '.config' / 'godeye' / 'rules.json')
        self.config_path = config_path
        self._rules: list[dict] = []
        self._load()

    def _load(self):
        path = Path(self.config_path)
        if not path.exists():
            print(
                f'[godeye] Warning: rules file not found at {self.config_path} — '
                'starting with no rules (all traffic shown).',
                file=sys.stderr,
            )
            self._rules = []
            return

        try:
            with open(path) as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f'[godeye] Warning: failed to load rules: {e}', file=sys.stderr)
            self._rules = []
            return

        compiled = []
        for rule in raw:
            compiled_rule = {}
            for field in _RULE_FIELDS:
                pattern = rule.get(field, '.*')
                compiled_rule[field] = re.compile(str(pattern), re.IGNORECASE)
            compiled.append(compiled_rule)
        self._rules = compiled

    def is_suppressed(self, pkt: dict) -> bool:
        """Return True if the packet matches any rule (should be suppressed)."""
        for rule in self._rules:
            if self._matches_rule(pkt, rule):
                return True
        return False

    def _matches_rule(self, pkt: dict, rule: dict) -> bool:
        """Return True only if ALL fields in the rule match the packet."""
        checks = {
            'process':       str(pkt.get('process', '')),
            'protocol':      str(pkt.get('protocol', '')),
            'local_ip':      str(pkt.get('local_ip', '')),
            'local_port':    str(pkt.get('local_port', '')),
            'local_domain':  str(pkt.get('local_domain', '')),
            'remote_ip':     str(pkt.get('remote_ip', '')),
            'remote_port':   str(pkt.get('remote_port', '')),
            'remote_domain': str(pkt.get('remote_domain', '')),
        }
        for field, regex in rule.items():
            value = checks.get(field, '')
            if not regex.search(value):
                return False
        return True

    @property
    def rule_count(self) -> int:
        return len(self._rules)
