"""Socket → process mapper: eBPF (preferred) with netstat fallback."""

import atexit
import ctypes
import logging
import re
import socket
import struct
import subprocess
import threading
import time

log = logging.getLogger('godeye.proc')

_CONN_CACHE_TTL = 30.0   # seconds before a cached 4-tuple entry expires
_PROC_RE        = re.compile(r'\d+/(?P<name>\S+)')
MISS            = (-1, '', '')

_TCP_PROTOS = frozenset({
    'tcp', 'ftp', 'ssh', 'smtp', 'http', 'pop3', 'imap',
    'https', 'smtps', 'imaps', 'pop3s', 'mysql', 'postgres', 'redis',
})
_UDP_PROTOS = frozenset({'udp', 'dhcp', 'ntp', 'snmp', 'ike', 'ike-nat', 'mdns'})


def _l4_candidates(proto: str) -> list[int]:
    """Translate an app-layer protocol name to IPPROTO number(s) to try."""
    if proto in _TCP_PROTOS: return [6]
    if proto in _UDP_PROTOS: return [17]
    return [6, 17]  # ambiguous (dns, icmp, …) — try both


def _read_proc(pid: int) -> tuple[str, str]:
    """Read (name, cmdline) from /proc/<pid>."""
    try:
        name = open(f'/proc/{pid}/comm').read().strip()
    except OSError:
        name = ''
    try:
        raw = open(f'/proc/{pid}/cmdline', 'rb').read(512)
        cmdline = raw.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
    except OSError:
        cmdline = ''
    return name, cmdline


def _proc_from_bpf(val) -> tuple[int, str, str]:
    """Extract (pid, name, cmdline) from a BPF map value."""
    pid = val.pid
    name, cmdline = _read_proc(pid)
    # /proc/<pid>/comm may be gone if the process exited; fall back to the
    # comm string the kernel recorded at the time of the syscall.
    if not name:
        name = bytes(val.comm).rstrip(b'\x00').decode('utf-8', errors='replace')
    return pid, name, cmdline


# ---------------------------------------------------------------------------
# Connection cache
# ---------------------------------------------------------------------------

class _ConnCache:
    """TTL-bounded (lip, lport, rip, rport) → (pid, name, cmdline) cache.

    Avoids re-resolving every packet on the same connection and bridges
    the window between packet arrival and BPF map population.
    """

    def __init__(self):
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, lip, lport, rip, rport):
        with self._lock:
            entry = self._data.get((lip, lport, rip, rport))
            if entry and time.monotonic() - entry[3] < _CONN_CACHE_TTL:
                return entry[:3]
        return None

    def put(self, lip, lport, rip, rport, pid, name, cmdline):
        with self._lock:
            self._data[(lip, lport, rip, rport)] = (pid, name, cmdline, time.monotonic())
            if len(self._data) > 2000:
                now = time.monotonic()
                stale = [k for k, v in self._data.items() if now - v[3] >= _CONN_CACHE_TTL]
                for k in stale:
                    del self._data[k]


# ---------------------------------------------------------------------------
# eBPF program
# ---------------------------------------------------------------------------
# Compiled at runtime by BCC/LLVM and loaded into the kernel.
# Hooks tcp_connect / tcp_sendmsg / tcp_recvmsg / tcp_close and
# udp_sendmsg / udp_recvmsg to maintain a (4-tuple + proto) → (pid, comm)
# map — no polling, no subprocess, no race window.
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
    u8  proto;
    u8  pad[3];  /* explicit padding — keeps hash stable across compilers */
};

/* NAT-resilient key: omits saddr so lookups survive source-IP rewriting
   (e.g. Docker MASQUERADE). sport+daddr+dport uniquely identify the flow. */
struct nat_key_t {
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

struct proc_info_t {
    u32  pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(conn_procs,  struct conn_key_t, struct proc_info_t, 16384);
BPF_HASH(conn_ports,  struct nat_key_t,  struct proc_info_t, 16384);

/* IPv6 variants of the same two maps */
struct conn_key6_t {
    u8  saddr[16];
    u8  daddr[16];
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

struct nat_key6_t {
    u8  daddr[16];
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

BPF_HASH(conn_procs6, struct conn_key6_t, struct proc_info_t, 16384);
BPF_HASH(conn_ports6, struct nat_key6_t,  struct proc_info_t, 16384);

static __always_inline void record_sock(struct sock *sk, u8 proto) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return;

    struct conn_key_t key = {};
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key.dport = bpf_ntohs(dport);
    key.proto = proto;

    struct proc_info_t info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    conn_procs.update(&key, &info);

    struct nat_key_t nkey = {};
    nkey.daddr = key.daddr;
    nkey.sport = key.sport;
    nkey.dport = key.dport;
    nkey.proto = proto;
    conn_ports.update(&nkey, &info);
}

static __always_inline void delete_sock(struct sock *sk, u8 proto) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return;

    struct conn_key_t key = {};
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key.dport = bpf_ntohs(dport);
    key.proto = proto;

    conn_procs.delete(&key);

    struct nat_key_t nkey = {};
    nkey.daddr = key.daddr;
    nkey.sport = key.sport;
    nkey.dport = key.dport;
    nkey.proto = proto;
    conn_ports.delete(&nkey);
}

static __always_inline void record_sock6(struct sock *sk, u8 proto) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET6)
        return;

    struct conn_key6_t key = {};
    bpf_probe_read_kernel(key.saddr, 16, sk->__sk_common.skc_v6_rcv_saddr.s6_addr);
    bpf_probe_read_kernel(key.daddr, 16, sk->__sk_common.skc_v6_daddr.s6_addr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key.dport = bpf_ntohs(dport);
    key.proto = proto;

    struct proc_info_t info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    conn_procs6.update(&key, &info);

    struct nat_key6_t nkey = {};
    __builtin_memcpy(nkey.daddr, key.daddr, 16);
    nkey.sport = key.sport;
    nkey.dport = key.dport;
    nkey.proto = proto;
    conn_ports6.update(&nkey, &info);
}

static __always_inline void delete_sock6(struct sock *sk, u8 proto) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET6)
        return;

    struct conn_key6_t key = {};
    bpf_probe_read_kernel(key.saddr, 16, sk->__sk_common.skc_v6_rcv_saddr.s6_addr);
    bpf_probe_read_kernel(key.daddr, 16, sk->__sk_common.skc_v6_daddr.s6_addr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key.dport = bpf_ntohs(dport);
    key.proto = proto;

    conn_procs6.delete(&key);

    struct nat_key6_t nkey = {};
    __builtin_memcpy(nkey.daddr, key.daddr, 16);
    nkey.sport = key.sport;
    nkey.dport = key.dport;
    nkey.proto = proto;
    conn_ports6.delete(&nkey);
}

/* TCP: hook connect (outbound) so the map is populated before the first
   packet hits the wire — eliminates the send/recv timing race. */
int kprobe__tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    record_sock(sk, PROTO_TCP);
    record_sock6(sk, PROTO_TCP);
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    record_sock(sk, PROTO_TCP);
    record_sock6(sk, PROTO_TCP);
    return 0;
}
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    record_sock(sk, PROTO_TCP);
    record_sock6(sk, PROTO_TCP);
    return 0;
}
int kprobe__tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    delete_sock(sk, PROTO_TCP);
    delete_sock6(sk, PROTO_TCP);
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    record_sock(sk, PROTO_UDP);
    record_sock6(sk, PROTO_UDP);
    return 0;
}
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    record_sock(sk, PROTO_UDP);
    record_sock6(sk, PROTO_UDP);
    return 0;
}
"""


# ---------------------------------------------------------------------------
# eBPF-backed mapper
# ---------------------------------------------------------------------------

class EBPFProcessMapper:
    """Maps sockets → processes via eBPF kernel hooks. No polling, no subprocesses."""

    def __init__(self):
        from bcc import BPF  # ImportError propagates to caller if BCC is missing
        self._bpf   = BPF(text=_EBPF_PROGRAM)
        self._cache = _ConnCache()
        atexit.register(self.cleanup)
        log.debug('eBPF process mapper loaded')

    def prefetch(self) -> None:
        pass  # the kernel keeps the BPF map current — nothing to prefetch

    def lookup(self,
               proto: str,
               local_ip: str,
               local_port: int,
               remote_ip: str = '',
               remote_port: int = 0):
        """Return (pid, name, cmdline), or MISS if the socket is unknown."""
        hit = self._cache.get(local_ip, local_port, remote_ip, remote_port)
        if hit:
            return hit

        try:
            result = self._bpf_lookup(proto, local_ip, local_port, remote_ip, remote_port)
            if result == MISS and remote_ip:
                # Reverse-orientation retry: if NAT rewrote the source IP
                # (e.g. Docker MASQUERADE) the socket's local IP won't match
                # the packet's src IP, so try the addresses swapped.
                result = self._bpf_lookup(proto, remote_ip, remote_port, local_ip, local_port)
        except Exception as exc:
            log.debug('eBPF lookup error: %s', exc)
            return MISS

        if result != MISS:
            self._cache.put(local_ip, local_port, remote_ip, remote_port, *result)
        return result

    def _bpf_lookup(self, proto, local_ip, local_port, remote_ip, remote_port):
        try:
            saddr = struct.unpack('I', socket.inet_aton(local_ip))[0]
        except OSError:
            return self._bpf_lookup_v6(proto, local_ip, local_port, remote_ip, remote_port)

        daddr = struct.unpack('I', socket.inet_aton(remote_ip))[0] if remote_ip else 0
        table, nat_table = self._bpf['conn_procs'], self._bpf['conn_ports']

        for proto_num in _l4_candidates(proto):
            # For UDP, also try (daddr=0, dport=0): unconnected UDP sockets
            # leave skc_daddr/skc_dport zeroed in the kernel struct.
            remote_opts = [(daddr, remote_port), (0, 0)] if proto_num == 17 else [(daddr, remote_port)]
            for sa in (saddr, 0):  # also try INADDR_ANY (socket bound to 0.0.0.0)
                for da, dp in remote_opts:
                    k = table.Key()
                    k.saddr, k.daddr, k.sport, k.dport, k.proto = sa, da, local_port, dp, proto_num
                    try:
                        result = _proc_from_bpf(table[k])
                        log.debug('eBPF: %s %s:%s→%s:%s → %s (pid %d)',
                                  proto, local_ip, local_port, remote_ip, remote_port,
                                  result[1], result[0])
                        return result
                    except KeyError:
                        pass

        # NAT fallback: match by (sport, daddr, dport) — saddr excluded because
        # MASQUERADE rewrites the source IP after the socket is already created.
        if daddr:
            for proto_num in _l4_candidates(proto):
                nk = nat_table.Key()
                nk.daddr, nk.sport, nk.dport, nk.proto = daddr, local_port, remote_port, proto_num
                try:
                    result = _proc_from_bpf(nat_table[nk])
                    log.debug('eBPF NAT: %s %s:%s→%s:%s → %s (pid %d)',
                              proto, local_ip, local_port, remote_ip, remote_port,
                              result[1], result[0])
                    return result
                except KeyError:
                    pass

        log.debug('eBPF: %s %s:%s→%s:%s not found', proto, local_ip, local_port, remote_ip, remote_port)
        return MISS

    def _bpf_lookup_v6(self, proto, local_ip, local_port, remote_ip, remote_port):
        zero16 = b'\x00' * 16
        try:
            saddr = socket.inet_pton(socket.AF_INET6, local_ip)
        except OSError:
            return MISS

        daddr = socket.inet_pton(socket.AF_INET6, remote_ip) if remote_ip else zero16
        table, nat_table = self._bpf['conn_procs6'], self._bpf['conn_ports6']
        pack = lambda b: (ctypes.c_uint8 * 16)(*b)  # bytes → ctypes array for BCC key

        for proto_num in _l4_candidates(proto):
            remote_opts = [(daddr, remote_port), (zero16, 0)] if proto_num == 17 else [(daddr, remote_port)]
            for sa in (saddr, zero16):
                for da, dp in remote_opts:
                    k = table.Key()
                    k.saddr, k.daddr, k.sport, k.dport, k.proto = pack(sa), pack(da), local_port, dp, proto_num
                    try:
                        result = _proc_from_bpf(table[k])
                        log.debug('eBPF IPv6: %s %s:%s→%s:%s → %s (pid %d)',
                                  proto, local_ip, local_port, remote_ip, remote_port,
                                  result[1], result[0])
                        return result
                    except KeyError:
                        pass

        if daddr != zero16:
            for proto_num in _l4_candidates(proto):
                nk = nat_table.Key()
                nk.daddr, nk.sport, nk.dport, nk.proto = pack(daddr), local_port, remote_port, proto_num
                try:
                    result = _proc_from_bpf(nat_table[nk])
                    log.debug('eBPF IPv6 NAT: %s %s:%s→%s:%s → %s (pid %d)',
                              proto, local_ip, local_port, remote_ip, remote_port,
                              result[1], result[0])
                    return result
                except KeyError:
                    pass

        log.debug('eBPF IPv6: %s %s:%s→%s:%s not found', proto, local_ip, local_port, remote_ip, remote_port)
        return MISS

    def cleanup(self) -> None:
        try:
            self._bpf.cleanup()
            log.debug('eBPF probes detached')
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Netstat-based fallback
# ---------------------------------------------------------------------------

class ProcessMapper:
    """Maps sockets → processes via netstat.

    Call prefetch() the moment a packet arrives so netstat runs in parallel
    with packet parsing. lookup() then collects the already-in-flight result
    instead of blocking on a fresh subprocess — critical for short-lived
    connections that vanish before they can be inspected.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._pending: subprocess.Popen | None = None
        self._cache   = _ConnCache()

    def prefetch(self) -> None:
        """Kick off netstat immediately. Safe to call from a packet callback."""
        with self._lock:
            if self._pending is not None:
                return  # previous snapshot still in-flight — reuse it
            try:
                self._pending = subprocess.Popen(
                    ['sudo', 'netstat', '-antulp'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                log.debug('netstat prefetch failed: %s', e)

    def lookup(self, proto: str, local_ip: str, local_port: int,
               remote_ip: str = '', remote_port: int = 0):
        """Return (pid, name, cmdline), or MISS if the socket is unknown."""
        hit = self._cache.get(local_ip, local_port, remote_ip, remote_port)
        if hit:
            return hit

        output = self._collect()
        result = self._parse(output, proto, local_ip, local_port, remote_ip, remote_port)
        if result != MISS:
            self._cache.put(local_ip, local_port, remote_ip, remote_port, *result)
        return result

    def _collect(self) -> bytes:
        """Wait for the prefetched netstat process, or run synchronously as fallback."""
        with self._lock:
            proc, self._pending = self._pending, None

        if proc is not None:
            try:
                stdout, _ = proc.communicate(timeout=5)
                return stdout
            except Exception as e:
                log.debug('netstat collect failed: %s', e)
                proc.kill()

        # Shouldn't reach here in normal use (prefetch() is always called first).
        try:
            return subprocess.run(
                ['sudo', 'netstat', '-antulp'], capture_output=True, timeout=5,
            ).stdout
        except Exception as e:
            log.debug('netstat sync failed: %s', e)
            return b''

    def _parse(self, output, proto, local_ip, local_port, remote_ip, remote_port):
        lines = [l for l in output.splitlines() if f'{local_ip}:{local_port}'.encode() in l]
        if remote_ip and remote_port:
            lines = [l for l in lines if f'{remote_ip}:{remote_port}'.encode() in l]

        for line in lines:
            m = _PROC_RE.search(line.decode(errors='replace'))
            if m:
                pid = int(m.group(0).split('/')[0])
                name, cmdline = _read_proc(pid)
                name = name or m.group('name').strip()
                log.debug('netstat: %s %s:%s→%s:%s → %s', proto, local_ip, local_port, remote_ip, remote_port, name)
                return (pid, name, cmdline)

        log.debug('netstat: %s %s:%s→%s:%s not found', proto, local_ip, local_port, remote_ip, remote_port)
        return MISS


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_process_mapper() -> tuple[object, str]:
    """Return (mapper, mode_label). Prefers eBPF; falls back to netstat."""
    try:
        return EBPFProcessMapper(), 'eBPF'
    except Exception as exc:
        log.warning('eBPF unavailable (%s); falling back to netstat', exc)
        return ProcessMapper(), 'netstat'
