# Multi Script

Debian 12 Recommended; run as root. The installer requests a TLS certificate for the primary domain only, using Cloudflare DNS validation.

Installation:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/eddyme23/eng/main/install-frimps.sh)
```

For a downloaded archive, extract it and run:

```bash
chmod +x *.sh
bash ./install-frimps.sh
```

## Protocols and ports

| Service | Public ports / path |
|---|---|
| OpenSSH | 22 |
| SSH WebSocket | 80, 8080, 8880, 2082, 2086 |
| SSH SSL and WebSocket TLS | 443 |
| OpenVPN Websocket | 80, 8080, 8880; path `/openvpn` |
| OpenVPN TLS | 443; path `/openvpn` |
| BHTTP | 90, 8081 |
| OpenVPN | TCP/UDP 1194; SSL 8433 |
| SlowDNS | UDP 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000-19999 |
| Hysteria 1 | UDP 20000-50000 |
| UDP Custom |UDP 50001-65535 |
| SocksIP | UDP 1195-3999 |
| BadVPN | 7300 |


Menu: `frimps-v6-menu` or `menu`.

### BHTTP capacity policy and verified updates

BHTTP fresh installs use the HEX RAM tiers: below 768 MB = 512 sessions,
below 1536 MB = 1024, below 3072 MB = 2048, below 6144 MB = 4096,
otherwise 8192. Set `BHTTP_MAX_SESSIONS=NUMBER` to override (1–8192).
These are concurrency ceilings, not guaranteed user capacity or speed.
The service retains sandboxing and a memory ceiling of half physical RAM,
capped at 4096 MB. It restarts after one second, including clean exits,
with at most three starts per minute to prevent a crash loop.

Existing production servers: `bash ./apply-bhttp-updates.sh`.
This downloads the pinned, SHA-256 verified v2.4.1 engine, runs its self-test,
backs up the current binary/unit/settings, applies RAM-based capacity, and
restarts BHTTP using the alternate-socket-safe helper. Existing ports, including
90 and 8180, are preserved. Existing sessions disconnect during activation.
Activation failure restores the saved engine and settings automatically.
Manual rollback: `bash ./apply-bhttp-updates.sh --rollback BACKUP_DIRECTORY`
using the directory printed by the updater. This updater intentionally does
not follow an unverified latest release or copy global TCP tuning.
