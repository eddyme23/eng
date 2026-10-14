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
| BHTTP | 8081 |
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

BHTTP now defaults to TCP 90. Existing installations can run `bash ./apply-bhttp-port.sh` to migrate their managed listener and SSH output from 8180 to 90. This restarts BHTTP and disconnects its sessions. The updater checks port availability, backs up its unit/settings and rolls back on update failure. Allow TCP 90 in any host/provider firewall. HCR ports remain 8881 and 8444.

BHTTP now supports TCP 90 and 8180 together. Run `bash ./apply-bhttp-port.sh` on an existing installation. The binary listens on 90; a systemd socket proxy forwards 8180 to the same instance so both ports share session state. Default fresh BHTTP installs configure both. The change disconnects existing BHTTP sessions. Permit both ports in any external firewall.

Only the production HCR installers and services are supported. The obsolete trial installers have been removed. Menu refresh retires the old managed trial unit once production HCR is active; account output uses only production settings. There are no separate trial users: HCR uses the same SSH accounts.

Fresh installations now include BHTTP (TCP 90 and 8180), HCR plain (TCP 8881) and HCR TLS (TCP 8444) by default. Their services start during installation, are enabled at boot and are checked before installation reports success. No extra flags are required. Explicit `V6_INSTALL_BHTTP=0`, `V6_INSTALL_HCR=0` or `V6_INSTALL_HCR_TLS=0` can skip the corresponding transport. Host/provider firewalls must allow the selected ports; client tests remain necessary.
