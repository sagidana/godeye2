"""Socket → process mapper using sudo netstat -antulp."""

import logging
import re
import subprocess
import threading

log = logging.getLogger('godeye.proc')

_PROC_RE = re.compile(r'\d+/(?P<name>\S+)')


class ProcessMapper:
    """
    Maps sockets to processes via netstat.

    Call prefetch() the instant a packet arrives so the netstat subprocess
    runs in parallel with packet parsing.  lookup() then collects the result
    (already in-flight) instead of spawning a new process, eliminating the
    delay that causes fast/short-lived connections to vanish before inspection.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: subprocess.Popen | None = None

    def prefetch(self) -> None:
        """
        Launch netstat immediately.  Safe to call from the packet-arrival
        callback before any parsing takes place.  If a previous prefetch is
        still running it is left intact (its snapshot is at least as fresh).
        """
        with self._lock:
            if self._pending is not None:
                return  # previous result still in-flight, reuse it
            try:
                self._pending = subprocess.Popen(
                    ['sudo', 'netstat', '-antulp'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                log.debug('netstat prefetch failed to start: %s', e)

    def lookup(self, proto: str, local_ip: str, local_port: int,
               remote_ip: str = '', remote_port: int = 0):
        """
        Collect the prefetched netstat result (or run synchronously as
        fallback) and search for the matching socket.
        Returns (pid, comm) or (-1, 'pid: -1') if not found.
        """
        # Grab the pending process atomically; a new prefetch can start after.
        with self._lock:
            proc = self._pending
            self._pending = None

        output = b''
        if proc is not None:
            try:
                stdout, _ = proc.communicate(timeout=5)
                output = stdout
            except Exception as e:
                log.debug('netstat collect failed: %s', e)
                proc.kill()
        else:
            # Fallback: no prefetch was started (shouldn't happen in normal use)
            log.debug('netstat: no prefetch available, running synchronously')
            try:
                result = subprocess.run(
                    ['sudo', 'netstat', '-antulp'],
                    capture_output=True, timeout=5,
                )
                output = result.stdout
            except Exception as e:
                log.debug('netstat fallback failed: %s', e)

        return self._parse(output, proto, local_ip, local_port, remote_ip, remote_port)

    def _parse(self, output: bytes, proto: str, local_ip: str, local_port: int,
               remote_ip: str, remote_port: int):
        local_filter = f'{local_ip}:{local_port}'.encode()
        lines = [l for l in output.splitlines() if local_filter in l]

        if remote_ip and remote_port:
            remote_filter = f'{remote_ip}:{remote_port}'.encode()
            lines = [l for l in lines if remote_filter in l]

        for line in lines:
            m = _PROC_RE.search(line.decode(errors='replace'))
            if m:
                comm = m.group('name').strip()
                pid_str = m.group(0).split('/')[0]
                log.debug('lookup %s %s:%s → %s:%s → %s',
                          proto, local_ip, local_port,
                          remote_ip, remote_port, comm)
                return (int(pid_str), comm)

        log.debug('lookup %s %s:%s → %s:%s not found',
                  proto, local_ip, local_port, remote_ip, remote_port)
        return (-1, 'pid: -1')
