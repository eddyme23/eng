# Multi Script

Optional browser account management: [ENG administration panel](PANEL.md).

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
| Xray VLESS / VMess WS and HTTPUpgrade | 80 NTLS / 443 TLS |
| Xray VLESS XHTTP | 80 NTLS / 443 TLS |
| Xray Trojan WebSocket | 443 TLS |
| Xray VLESS REALITY + Vision | 443 TCP |
| Xray VLESS / VMess / Trojan gRPC | 443 TLS, HTTP/2 |
| Shadowsocks 2022 | 8388 TCP |
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
