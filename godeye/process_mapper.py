"""Socket → process mapper: eBPF (preferred) with netstat fallback."""

import atexit
import logging
import re
import socket
import struct
import subprocess
import threading

log = logging.getLogger('godeye.proc')

_PROC_RE = re.compile(r'\d+/(?P<name>\S+)')

# ---------------------------------------------------------------------------
# eBPF program — compiled at runtime by BCC/LLVM and loaded into the kernel.
# Hooks tcp_sendmsg / tcp_recvmsg / tcp_close and udp_sendmsg / udp_recvmsg
# to build a (4-tuple + proto) → (pid, comm) map without any subprocess or
# /proc polling.
# ---------------------------------------------------------------------------

_EBPF_PROGRAM = r"""
#include <linux/ptrace.h>
#include <net/sock.h>

#define PROTO_TCP 6
#define PROTO_UDP 17

struct conn_key_t {
    u32 saddr;   /* local IP,   network byte order */
    u32 daddr;   /* remote IP,  network byte order */
    u16 sport;   /* local port, host byte order    */
    u16 dport;   /* remote port, host byte order   */
    u8  proto;   /* IPPROTO_TCP or IPPROTO_UDP     */
    u8  pad[3];  /* explicit padding — keep hash stable */
};

struct proc_info_t {
    u32  pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(conn_procs, struct conn_key_t, struct proc_info_t, 16384);

static __always_inline void record_sock(struct sock *sk, u8 proto) {
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        return;

    struct conn_key_t key = {};
    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.sport = sk->__sk_common.skc_num;                   /* host byte order */
    key.dport = bpf_ntohs(sk->__sk_common.skc_dport);     /* net → host      */
    key.proto = proto;

    struct proc_info_t info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    conn_procs.update(&key, &info);
}

static __always_inline void delete_sock(struct sock *sk, u8 proto) {
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        return;

    struct conn_key_t key = {};
    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.sport = sk->__sk_common.skc_num;
    key.dport = bpf_ntohs(sk->__sk_common.skc_dport);
    key.proto = proto;

    conn_procs.delete(&key);
}

/* TCP: record on every send/recv, clean up on close */
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    record_sock((struct sock *)PT_REGS_PARM1(ctx), PROTO_TCP);
    return 0;
}
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    record_sock((struct sock *)PT_REGS_PARM1(ctx), PROTO_TCP);
    return 0;
}
int kprobe__tcp_close(struct pt_regs *ctx) {
    delete_sock((struct sock *)PT_REGS_PARM1(ctx), PROTO_TCP);
    return 0;
}

/* UDP: record on every send/recv */
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    record_sock((struct sock *)PT_REGS_PARM1(ctx), PROTO_UDP);
    return 0;
}
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
    record_sock((struct sock *)PT_REGS_PARM1(ctx), PROTO_UDP);
    return 0;
}
"""

# App-protocol strings → L4 protocol number (for eBPF map key).
# Ambiguous ones (e.g. 'dns' can be TCP or UDP) → try both.
_TCP_APP_PROTOS = frozenset({
    'tcp', 'ftp', 'ssh', 'smtp', 'http', 'pop3', 'imap',
    'https', 'smtps', 'imaps', 'pop3s', 'mysql', 'postgres', 'redis',
})
_UDP_APP_PROTOS = frozenset({
    'udp', 'dhcp', 'ntp', 'snmp', 'ike', 'ike-nat', 'mdns',
})


def _l4_candidates(proto: str) -> list[int]:
    """Return the L4 protocol number(s) to try for a given app-layer proto name."""
    if proto in _TCP_APP_PROTOS:
        return [6]
    if proto in _UDP_APP_PROTOS:
        return [17]
    return [6, 17]   # 'dns', 'icmp', numeric — try both


# ---------------------------------------------------------------------------
# eBPF-backed mapper
# ---------------------------------------------------------------------------

class EBPFProcessMapper:
    """
    Maps sockets to processes via eBPF hooks in the kernel.

    The kernel updates the BPF hash map synchronously at the moment of each
    tcp/udp send or recv syscall — no polling, no subprocess, no race window.
    Probes are automatically detached and the program unloaded when the process
    exits (kernel refcount drops to zero), but cleanup() may also be called
    explicitly.
    """

    def __init__(self):
        from bcc import BPF  # ImportError propagates to caller if BCC missing
        self._bpf = BPF(text=_EBPF_PROGRAM)
        # kprobe__ prefix causes BCC to auto-attach to the named kernel function
        atexit.register(self.cleanup)
        log.debug('eBPF process mapper loaded')

    def prefetch(self) -> None:
        """No-op: the kernel keeps the BPF map current without any polling."""

    def lookup(self, proto: str, local_ip: str, local_port: int,
               remote_ip: str = '', remote_port: int = 0):
        """Query the BPF map; returns (pid, comm) or (-1, 'pid: -1')."""
        try:
            return self._lookup(proto, local_ip, local_port, remote_ip, remote_port)
        except Exception as exc:
            log.debug('eBPF lookup error: %s', exc)
            return (-1, 'pid: -1')

    def _lookup(self, proto, local_ip, local_port, remote_ip, remote_port):
        try:
            saddr = struct.unpack('I', socket.inet_aton(local_ip))[0]
        except OSError:
            return (-1, 'pid: -1')   # IPv6 — not yet supported

        daddr = 0
        if remote_ip:
            try:
                daddr = struct.unpack('I', socket.inet_aton(remote_ip))[0]
            except OSError:
                pass

        table = self._bpf['conn_procs']

        # Try each candidate L4 proto, and for each also try INADDR_ANY (0)
        # as the local address in case the socket was bound to 0.0.0.0.
        for proto_num in _l4_candidates(proto):
            for sa in (saddr, 0):
                key = table.Key()
                key.saddr = sa
                key.daddr = daddr
                key.sport = local_port
                key.dport = remote_port
                key.proto = proto_num
                try:
                    val = table[key]
                    comm = bytes(val.comm).rstrip(b'\x00').decode('utf-8', errors='replace')
                    log.debug('eBPF: %s %s:%s→%s:%s → %s (pid %d)',
                              proto, local_ip, local_port,
                              remote_ip, remote_port, comm, val.pid)
                    return (val.pid, comm)
                except KeyError:
                    pass

        log.debug('eBPF: %s %s:%s→%s:%s not found',
                  proto, local_ip, local_port, remote_ip, remote_port)
        return (-1, 'pid: -1')

    def cleanup(self) -> None:
        """Detach all eBPF probes and unload the program from the kernel."""
        try:
            self._bpf.cleanup()
            log.debug('eBPF probes detached')
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Netstat-based fallback (original implementation)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_process_mapper() -> tuple[object, str]:
    """
    Return (mapper, mode_label).  Tries eBPF first; falls back to netstat
    if BCC is not installed or the kernel doesn't support it.
    """
    try:
        mapper = EBPFProcessMapper()
        return (mapper, 'eBPF')
    except Exception as exc:
        log.warning('eBPF unavailable (%s); falling back to netstat', exc)
        return (ProcessMapper(), 'netstat')
