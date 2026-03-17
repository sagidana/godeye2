# godeye

Network traffic monitor for Linux — maps live packets to processes in real time.

## Features

- Captures packets on any (or all) network interfaces
- Maps connections to the owning process via `/proc`
- Resolves IPs to hostnames using passive DNS tracking
- Suppresses known/expected traffic via a JSON rules file
- Rich terminal output with optional verbose mode

## Requirements

- Linux (uses `/proc` for process mapping)
- Python 3.10+
- Root privileges or `CAP_NET_RAW` capability

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e .
```

## Usage

```bash
sudo godeye [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `-i INTERFACE` | Capture on a specific interface (default: all) |
| `-c CONFIG` | Path to rules file (default: `~/.config/godeye/rules.json`) |
| `-v` | Verbose mode — also show suppressed/matched packets (dimmed) |

### Examples

```bash
# Monitor all interfaces
sudo godeye

# Monitor a specific interface
sudo godeye -i eth0

# Verbose mode with a custom rules file
sudo godeye -v -c /etc/godeye/rules.json
```

## Rules

Create `~/.config/godeye/rules.json` to suppress expected traffic. Example:

```json
[
  {"dst_host": "connectivity-check.ubuntu.com"},
  {"dst_port": 53},
  {"process": "firefox", "dst_port": 443}
]
```

Packets matching any rule are hidden by default (shown dimmed in `-v` mode).

## License

MIT
