# Frimps / ENG Multi Script

Debian 12; run as root. The installer requests a TLS certificate for the primary domain only, using Cloudflare DNS validation.

Install from this repository:

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
| ZiVPN | UDP 6000–19999 |
| Hysteria 1 | UDP 20000–50000 |
| UDP Custom | Remaining UDP ports after dedicated reservations |
| BadVPN | Local helper 7300 |

HAProxy owns the shared public TCP ports. Nginx uses loopback 9080/9081; Dropbear uses loopback 143. TCP and UDP 443 are separate listeners.

GF HTTP payload handling is built directly into payloadgate; no separate Node gateway or port 3104 is needed. Standard SSH WebSocket clients use the framing bridge. BShield uses an HTTP 101 upgrade followed by raw OpenVPN bytes, not RFC 6455 frames. Direct SSH SSL clients that wait for a server banner fall back to SSH after two seconds of inactivity following the TLS handshake.

Menu: `frimps-v6-menu` or `menu`. State: `/etc/frimps-v6`.

A menu refresh copies scripts but does not replace active proxy configurations or rebuild Go gateways. Apply transport changes by rendering, validating, rebuilding and staging the core, then using the activation workflow on a fresh/test VPS. Existing installations with older service/state paths require a separate migration.

Run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live` after installation. Live Debian proxy configuration and full VPN client tests remain required.
