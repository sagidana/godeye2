"""Socket → process mapper using sudo netstat -antulp."""

import logging
import re
import subprocess

log = logging.getLogger('godeye.proc')

_PROC_RE = re.compile(r'\d+/(?P<name>\S+)')


class ProcessMapper:
    def lookup(self, proto: str, local_ip: str, local_port: int,
               remote_ip: str = '', remote_port: int = 0):
        """
        Run sudo netstat -antulp, grep for local and remote addr:port,
        and return (pid, comm).  Returns (-1, 'pid: -1') if not found.
        """
        try:
            netstat = subprocess.run(
                ['sudo', 'netstat', '-antulp'],
                capture_output=True, timeout=5,
            )
            output = netstat.stdout

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

        except Exception as e:
            log.debug('netstat failed: %s', e)

        log.debug('lookup %s %s:%s → %s:%s not found',
                  proto, local_ip, local_port, remote_ip, remote_port)
        return (-1, 'pid: -1')
