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
| OpenVPN TLS | 443; path `/openvpn` |
| OpenVPN | TCP/UDP 1194; SSL 8433 |
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

## App device SSH credentials

[App certificate setup and app/generator handoff](APP-SSH-AUTH.md) adds
operator-approved per-device OpenSSH certificates alongside existing password
accounts. TG/Gen pin export and optional certificate-only SSH account policies
are available; ordinary accounts retain password access. No automatic enrollment
or app-identity attestation is included.
