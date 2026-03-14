# Firewallo

**Firewallo** is a zone-based firewall manager for Debian GNU/Linux supporting both **nftables** and **iptables** backends.

Written in pure C with no external dependencies — only the standard C library and POSIX APIs. Includes a CLI tool, a REST API, and a web interface.

## Features

- **Zone-based architecture** — 5 zones (FW, LAN, WAN, DMZ, VPN) with 25 inter-zone filter chains
- **Dual backend** — nftables (primary) and iptables (legacy), switchable at runtime
- **Single JSON config** — one file to backup/restore the entire firewall configuration
- **REST API** — full control under `/api/v1/` (config, rules, NAT, lifecycle)
- **Web interface** — vanilla HTML/JS/CSS dashboard with dark theme
- **CLI tool** — `firewallo start|stop|restart|reset|status|validate|export|restore`
- **NAT** — MASQUERADE, SNAT, DNAT
- **Security** — TCP flag detection, stateful tracking, DNS restriction, ICMP filtering
- **DPI** — Suricata integration for deep packet inspection
- **WireGuard** — VPN interface support
- **i18n** — English and Italian
- **No external libraries** — pure C17 + POSIX

## Supported OS

- Debian 12+

## Architecture

Firewallo currently supports **IPv4 only** by design (`ip` family in nftables, not `inet`). All DNS traffic is restricted to configured servers and root servers. Default policy is DROP on all chains.

**Default open ports (LAN to WAN):**
- TCP: 20, 21, 22, 23, 25, 80, 110, 143, 443, 995
- UDP: 123

All LAN ranges are automatically NATed (masquerade) to WAN interfaces. DMZ ranges are excluded from masquerade.

## Quick Start

### Build from source

```bash
git clone https://github.com/un1x80/firewallo.git
cd firewallo
make
```

This produces two binaries in `build/`:
- `firewallo` — CLI tool
- `firewallo-web` — HTTP server with REST API and web frontend

### Install

```bash
sudo make install
```

Or build a `.deb` package:

```bash
sudo ./debian/build-deb.sh
sudo apt install ./firewallo_2.0.0_amd64.deb
```

### Configure

Edit `/etc/firewallo/firewallo.json` — the single configuration file containing all interfaces, DNS servers, filter chains, NAT rules, and more.

### Usage

```bash
# Validate your config
firewallo validate

# Dry-run (show commands without executing)
firewallo -n start

# Start the firewall (requires root)
sudo firewallo start

# View status
firewallo -c /path/to/firewallo.json status

# Stop / restart / reset
sudo firewallo stop
sudo firewallo restart
sudo firewallo reset

# Export / restore config backup
firewallo export
firewallo restore firewallo-backup-20260101-120000.json

# Switch backend
firewallo switch nft
firewallo switch ipt

# Start web interface
firewallo-web --port 8080 --webroot /usr/local/share/firewallo/web --config /etc/firewallo/firewallo.json
```

### Systemd

```bash
sudo systemctl enable firewallo
sudo systemctl start firewallo

sudo systemctl enable firewallo-web
sudo systemctl start firewallo-web
# Open http://localhost:8080
```

## REST API

All endpoints under `/api/v1/`. Responses use `{"error": false, "data": ...}` envelope.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/version` | Version and backend info |
| GET/PUT | `/api/v1/config` | Full configuration |
| GET | `/api/v1/config/interfaces` | Interface assignments |
| GET | `/api/v1/config/dns` | DNS servers |
| GET/PUT | `/api/v1/config/backend` | Backend (nft/ipt) |
| GET | `/api/v1/filter` | All 25 chains overview |
| GET | `/api/v1/filter/{chain}` | Chain detail |
| POST | `/api/v1/filter/{chain}/tcp` | Add TCP port `{"port": 80}` |
| DELETE | `/api/v1/filter/{chain}/tcp/{port}` | Remove TCP port |
| POST | `/api/v1/filter/{chain}/udp` | Add UDP port |
| DELETE | `/api/v1/filter/{chain}/udp/{port}` | Remove UDP port |
| GET | `/api/v1/nat` | NAT rules |
| POST | `/api/v1/firewall/start` | Start firewall |
| POST | `/api/v1/firewall/stop` | Stop firewall |
| POST | `/api/v1/firewall/restart` | Restart firewall |
| POST | `/api/v1/firewall/reset` | Reset firewall |
| GET | `/api/v1/firewall/status` | Status (active/inactive) |
| GET | `/api/v1/firewall/rules` | Active ruleset |
| GET | `/api/v1/validate` | Validate config |

## Project Structure

```
firewallo/
├── src/lib/         # Core library (JSON parser, config, rule compiler, backends)
├── src/cli/         # CLI binary
├── src/web/         # HTTP server binary
├── include/         # Public headers
├── web/             # Frontend (HTML/CSS/JS)
├── etc/firewallo/   # Default config (firewallo.json)
├── tests/           # Test suite
├── systemd/         # Service files
├── debian/          # .deb packaging
├── legacy/          # Original bash scripts (reference)
└── Makefile
```

## Development

```bash
# Build with debug symbols + AddressSanitizer
make debug

# Run tests (344 tests across 4 suites)
make test

# Clean build artifacts
make clean
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

## Uninstall

```bash
sudo apt autoremove firewallo -y
```
