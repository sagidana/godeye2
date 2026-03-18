"""Load rules.json, compile regexes, and match packets."""

import json
import logging
import re
import sys
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger('godeye.rules')

_WATCH_INTERVAL = 1.0  # seconds between mtime checks

_RULE_FIELDS = [
    'process', 'protocol', 'local_ip', 'local_port', 'local_domain',
    'remote_ip', 'remote_port', 'domain',
]

_DEFAULT_PATTERN = re.compile('.*', re.IGNORECASE)


class RuleEngine:
    """Loads rules from JSON and matches packet dicts against them."""

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path.home() / '.config' / 'godeye' / 'rules.json')
        self.config_path = config_path
        self._rules: list[dict] = []
        self._lock = threading.Lock()
        self._mtime: float = 0.0
        self._load()
        self._start_watcher()

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
                content = f.read()
        except OSError as e:
            print(f'[godeye] Warning: failed to load rules: {e}', file=sys.stderr)
            self._rules = []
            return

        # Support both a JSON array and JSONL (one object per line)
        try:
            raw = json.loads(content)
            if isinstance(raw, dict):
                raw = [raw]
        except json.JSONDecodeError:
            raw = []
            for lineno, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f'[godeye] Warning: skipping bad rule on line {lineno}: {e}', file=sys.stderr)

        compiled = []
        for rule in raw:
            compiled_rule = {}
            for field in _RULE_FIELDS:
                pattern = rule.get(field, '.*')
                compiled_rule[field] = re.compile(str(pattern), re.IGNORECASE)
            compiled.append(compiled_rule)
        try:
            self._mtime = Path(self.config_path).stat().st_mtime
        except OSError:
            self._mtime = 0.0
        with self._lock:
            self._rules = compiled
        log.debug('loaded %d rules from %s', len(self._rules), self.config_path)
        for i, (raw_rule, _) in enumerate(zip(raw, compiled)):
            log.debug('  rule[%d]: %s', i, raw_rule)

    def is_suppressed(self, pkt: dict) -> bool:
        """Return True if the packet matches any rule (should be suppressed)."""
        log.debug('checking packet: process=%r protocol=%r domain=%r remote_ip=%r',
                  pkt.get('process'), pkt.get('protocol'),
                  pkt.get('domain'), pkt.get('remote_ip'))
        with self._lock:
            rules = self._rules
        for i, rule in enumerate(rules):
            if self._matches_rule(pkt, rule, rule_index=i):
                log.debug('  → suppressed by rule[%d]', i)
                return True
        log.debug('  → not suppressed')
        return False

    def _start_watcher(self) -> None:
        t = threading.Thread(target=self._watch, daemon=True)
        t.start()

    def _watch(self) -> None:
        while True:
            time.sleep(_WATCH_INTERVAL)
            try:
                mtime = Path(self.config_path).stat().st_mtime
            except OSError:
                continue
            if mtime != self._mtime:
                log.debug('rules file changed, reloading')
                self._load()
                print(f'[godeye] Rules reloaded ({self.rule_count} rules).', file=sys.stderr)

    def _matches_rule(self, pkt: dict, rule: dict, rule_index: int = -1) -> bool:
        """Return True only if ALL fields in the rule match the packet."""
        checks = {
            'process':       str(pkt.get('process', '')),
            'protocol':      str(pkt.get('protocol', '')),
            'local_ip':      str(pkt.get('local_ip', '')),
            'local_port':    str(pkt.get('local_port', '')),
            'local_domain':  str(pkt.get('local_domain', '')),
            'remote_ip':     str(pkt.get('remote_ip', '')),
            'remote_port':   str(pkt.get('remote_port', '')),
            'domain':        str(pkt.get('domain', '')),
        }
        for field, regex in rule.items():
            value = checks.get(field, '')
            if not regex.search(value):
                log.debug('  rule[%d] NO MATCH: field=%s pattern=%r value=%r',
                          rule_index, field, regex.pattern, value)
                return False
        return True

    @property
    def rule_count(self) -> int:
        return len(self._rules)
