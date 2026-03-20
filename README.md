# godeye

Network traffic monitor for Linux — maps live packets to processes in real time.

## Features

- Captures packets on any (or all) network interfaces
- Maps connections to the owning process via `/proc`
- Resolves IPs to hostnames using passive DNS tracking
- Suppresses known/expected traffic via a JSON rules file
- Rich terminal output with optional verbose mode
- Desktop OSD notifications for unfiltered packets

## Requirements

- Linux (uses `/proc` for process mapping)
- Python 3.10+
- Root privileges or `CAP_NET_RAW` capability
- `python3-bcc` (BPF Compiler Collection — installed automatically by `godeye init`)
- `notify-send` or `osd_cat` (optional, for desktop notifications)

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e .
```

After installing, run the init command once to set up the system symlink and install the `bcc` dependency:

```bash
sudo ~/.penv/versions/godeye/bin/godeye init
```

> **Note:** `sudo $(which godeye)` will not work if godeye is installed in a pyenv virtualenv, as `which` resolves to the shim rather than the real binary. Use the full path to the binary instead.

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
| `--notify` | Show unfiltered packets as desktop notifications (`notify-send` or `osd_cat`) |

### Examples

```bash
# Monitor all interfaces
sudo godeye

# Monitor a specific interface
sudo godeye -i eth0

# Verbose mode with a custom rules file
sudo godeye -v -c /etc/godeye/rules.json

# With desktop notifications
sudo godeye --notify
```

## Init

The `init` command sets up godeye's system dependencies:

```bash
sudo ~/.penv/versions/godeye/bin/godeye init
```

It does two things:

1. Creates a `/usr/bin/godeye` symlink so `sudo godeye` works correctly across all shell environments (including those where pyenv or virtualenvs are not on root's PATH).
2. Installs `python3-bcc` (BPF Compiler Collection Python bindings) via the system package manager (`pacman`, `apt-get`, `dnf`, or `zypper`), then symlinks it into the running Python's site-packages if needed.

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
