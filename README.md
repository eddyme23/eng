# Frimps / ENG Multi Script

Debian 12; run as root. The installer requests a TLS certificate for the primary domain only, using Cloudflare DNS validation.

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
| OpenSSH | TCP 22 |
| SSH payload / SSH WebSocket | TCP 80, 8080, 8880, 2082, 2086; WebSocket path `/` |
| SSH direct SSL and WebSocket TLS | TCP 443; WebSocket path `/` |
| BShield / OpenVPN HTTP upgrade | TCP 80, 8080, 8880; path `/openvpn` |
| BShield / OpenVPN HTTP upgrade over TLS | TCP 443; path `/openvpn` |
| OpenVPN | TCP/UDP 1194; direct SSL TCP 8433 |
| SlowDNS | UDP 53 |
| Hysteria 2 | UDP 443 |
| WireGuard | UDP 4000 |
| ZiVPN | UDP 6000â€“19999 |
| Hysteria 1 | UDP 20000â€“50000 |
| UDP Custom | Remaining UDP ports after dedicated reservations |
| BadVPN | Local helper 7300 |

HAProxy owns the shared public TCP ports. Nginx uses loopback 9080/9081; Dropbear uses loopback 143. TCP and UDP 443 are separate listeners.

Menu: `frimps-v6-menu` or `menu`.

Run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live` after installation. Live Debian proxy configuration and full VPN client tests remain required.

## Apply connection startup fixes to an installed server

```bash
git pull --ff-only origin main
bash ./apply-connection-fixes.sh
```
