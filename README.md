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
| SSH SSL and SSH WebSocket TLS | 443 |
| OpenVPN Websocket | 80, 8080, 8880; path `/openvpn` |
| OpenVPN TLS | 8433; path `/openvpn` |
| OpenVPN | TCP/UDP 1194 |
| BHTTP | 90, 8081, 8180 |
| HCR | 8881 NTLS / 8444 TLS |
| DNSTT | UDP/DoH/DoT 53 |
| VayDNS | UDP/DoH/DoT 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000-19999 |
| Hysteria 1 | UDP 20000-50000 |
| UDP Custom |UDP 50001-65535 |
| SocksIP | UDP 1195-3999 |
| BadVPN | 7300 |


Menu: `frimps-v6-menu` or `menu`.

## SlowDNS automatic verification

`bash ./slowdns-audit.sh` verifies the running service, keys, SSH backend and an
actual encrypted DNSTT-to-SSH stream using the pinned/checksummed cached client.
It also checks parent DNS delegation and whether delegated NS IPv4 addresses
match the VPS (with public NAT-address discovery when needed). `--local` skips
public DNS queries. Missing probe tools are reported as skipped, not verified;
checksum failures and actual probe failures fail the audit. Checks never rebuild
or restart the working server or change its keys, MTU, accounts or routing.

Recent log summaries separate encrypted authentication failures from stream
starts in other sessions. Empty logs are neutral. A successful encrypted server
probe is not proof of phone/carrier browsing or SSH account authentication.
Manual troubleshooting is only prompted when the audit finds a problem; use
`slowdns-flow-audit.sh SSH_USERNAME` for a reported client/browsing issue.
