"""Desktop OSD overlay for unfiltered packets (notify-send or osd_cat fallback)."""

import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# File logger — always writes to /tmp/godeye.log regardless of root logging config
# ---------------------------------------------------------------------------
_log = logging.getLogger('godeye.notify')
if not _log.handlers:
    _fh = logging.FileHandler('/tmp/godeye.log')
    _fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [notify] %(message)s'))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)
    _log.propagate = False


def _find_backend() -> Optional[str]:
    ns_path = shutil.which('notify-send')
    osd_path = shutil.which('osd_cat')
    _log.debug('backend detection: notify-send=%s  osd_cat=%s', ns_path, osd_path)
    if ns_path:
        _log.debug('selected backend: notify-send (%s)', ns_path)
        return 'notify-send'
    if osd_path:
        _log.debug('selected backend: osd_cat (%s)', osd_path)
        return 'osd_cat'
    _log.warning('no notification backend found (notify-send and osd_cat both absent from PATH)')
    return None

_BACKEND: Optional[str] = _find_backend()


class _RateLimiter:
    """Token bucket + per-(process, remote) dedup window."""

    def __init__(self, capacity=5, refill_rate=2.0, dedup_window=30.0):
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._dedup_window = dedup_window
        self._tokens: float = float(capacity)
        self._last_refill = time.monotonic()
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            elapsed = now - self._last_refill
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
            self._last_refill = now
            since_last = now - self._seen.get(key, 0.0)
            if since_last < self._dedup_window:
                _log.debug('rate-limited (dedup): key=%r  %.1fs since last', key, since_last)
                return False
            if self._tokens < 1.0:
                _log.debug('rate-limited (token bucket exhausted): key=%r  tokens=%.2f', key, self._tokens)
                return False
            self._tokens -= 1.0
            self._seen[key] = now
            if len(self._seen) > 500:
                cutoff = now - self._dedup_window
                self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
            return True


class Notifier:
    def __init__(self):
        self._rl = _RateLimiter()
        _log.info('Notifier created  backend=%s  SUDO_USER=%s', _BACKEND, os.environ.get('SUDO_USER'))

    @property
    def available(self) -> bool:
        return _BACKEND is not None

    def notify(self, pkt: dict) -> None:
        if _BACKEND is None:
            return
        try:
            process = pkt.get('process') or 'unknown'
            remote = pkt.get('domain') or pkt.get('remote_ip', '?')
            key = f"{process}\x00{remote}"
            if not self._rl.allow(key):
                return
            proto = pkt['protocol'].upper()
            remote_port = pkt.get('remote_port', '')
            direction = '\u2192' if pkt.get('src_port') == pkt.get('local_port') else '\u2190'
            summary = f"{process}  {direction}  {remote}:{remote_port}"
            body = f"{proto}  {pkt.get('local_ip', '')}:{pkt.get('local_port', '')}"
            _log.debug('dispatching notification: summary=%r  body=%r  backend=%s', summary, body, _BACKEND)
            if _BACKEND == 'notify-send':
                _send_notify(summary, body)
            else:
                _send_osd(summary)
        except Exception:
            _log.exception('unhandled exception in notify()')


def _user_session_env(username: str) -> dict[str, str]:
    """Read DISPLAY/DBUS vars from a live process owned by username via /proc,
    then fill in any missing values from well-known systemd paths."""
    want = {'DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR'}
    result: dict[str, str] = {}
    uid = None
    try:
        import pwd
        uid = pwd.getpwnam(username).pw_uid
        _log.debug('scanning /proc for uid=%d (user=%s)', uid, username)
        for pid_entry in os.scandir('/proc'):
            if not pid_entry.name.isdigit():
                continue
            try:
                if os.stat(pid_entry.path).st_uid != uid:
                    continue
                with open(f'/proc/{pid_entry.name}/environ', 'rb') as f:
                    for item in f.read().split(b'\x00'):
                        if b'=' not in item:
                            continue
                        k, _, v = item.partition(b'=')
                        key = k.decode('utf-8', errors='replace')
                        if key in want:
                            result[key] = v.decode('utf-8', errors='replace')
                if result:
                    _log.debug('found session env from pid %s: %s', pid_entry.name, result)
                    break
            except OSError:
                continue
    except Exception:
        _log.exception('_user_session_env failed for user=%r', username)

    # Systemd user sessions expose the D-Bus socket at a well-known path that
    # is rarely exported into process environments.  Fill in the gap explicitly.
    if uid is not None and 'DBUS_SESSION_BUS_ADDRESS' not in result:
        candidate = f'unix:path=/run/user/{uid}/bus'
        if os.path.exists(f'/run/user/{uid}/bus'):
            result['DBUS_SESSION_BUS_ADDRESS'] = candidate
            _log.debug('DBUS_SESSION_BUS_ADDRESS not in /proc environ; '
                       'using systemd well-known path: %s', candidate)
        else:
            _log.warning('DBUS_SESSION_BUS_ADDRESS missing and %s does not exist', candidate)

    if 'XDG_RUNTIME_DIR' not in result and uid is not None:
        xdg = f'/run/user/{uid}'
        if os.path.isdir(xdg):
            result['XDG_RUNTIME_DIR'] = xdg
            _log.debug('XDG_RUNTIME_DIR filled from well-known path: %s', xdg)

    _log.debug('final session env for %r: %s', username, result)
    return result


def _send_notify(summary: str, body: str) -> None:
    cmd = [
        'notify-send',
        '--app-name=godeye',
        '--urgency=low',
        '--expire-time=2000',
        '--icon=network-transmit-receive',
        '--hint=int:transient:1',
        summary,
    ]
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user:
        session_env = _user_session_env(sudo_user)
        if not session_env:
            _log.warning('proceeding without session env — notify-send will likely fail silently')
        # Pass vars via `env KEY=VAL` after the user switch so sudo env_reset
        # cannot strip them before notify-send sees them.
        env_args = [f'{k}={v}' for k, v in session_env.items()]
        cmd = ['sudo', '-u', sudo_user, '--', 'env'] + env_args + cmd
    _log.debug('Popen cmd=%s', cmd)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True)
        # Wait briefly to catch fast failures (e.g. sudo error, dbus error)
        try:
            out, err = proc.communicate(timeout=2)
            if proc.returncode != 0:
                _log.warning('notify-send exited %d  stdout=%r  stderr=%r',
                             proc.returncode, out.decode(errors='replace'), err.decode(errors='replace'))
            else:
                _log.debug('notify-send succeeded (rc=0)')
        except subprocess.TimeoutExpired:
            # Still running after 2s — that's fine, don't block
            _log.debug('notify-send still running after 2s timeout (normal for some daemons)')
    except OSError:
        _log.exception('OSError launching notify-send cmd=%s', cmd)


def _send_osd(line: str) -> None:
    try:
        proc = subprocess.Popen(
            ['osd_cat', '--delay=2', '--color=grey', '--pos=top', '--align=right',
             '--outline=0', '--font=-*-*-medium-r-normal-*-12-*-*-*-*-*-*-*'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
        )
        proc.stdin.write((line + '\n').encode())
        proc.stdin.close()
        _log.debug('osd_cat launched for line=%r', line)
        # Don't .wait() — osd_cat blocks for --delay seconds
    except OSError:
        _log.exception('OSError launching osd_cat')
