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

GF HTTP payload handling is built directly into payloadgate; no separate Node gateway or port 3104 is needed. Standard SSH WebSocket clients use the framing bridge. BShield uses an HTTP 101 upgrade followed by raw OpenVPN bytes, not RFC 6455 frames. Direct SSH SSL clients that wait for a server banner fall back to SSH after 250 ms of inactivity following the TLS handshake.

Menu: `frimps-v6-menu` or `menu`. State: `/etc/frimps-v6`.

A menu refresh copies scripts but does not replace active proxy configurations or rebuild Go gateways. Apply transport changes by rendering, validating, rebuilding and staging the core, then using the activation workflow on a fresh/test VPS. Existing installations with older service/state paths require a separate migration.

Run `bash ./postflight-v6.sh` and `bash ./protocol-health-v6.sh --live` after installation. Live Debian proxy configuration and full VPN client tests remain required.

## Apply connection startup fixes to an installed server

```bash
git pull --ff-only origin main
bash ./apply-connection-fixes.sh
```

This rebuilds the TLS gateway, validates and reloads HAProxy routing, and refreshes the menu. It backs up the previous TLS gateway and public proxy configuration. Restarting the TLS gateway disconnects existing connections on TCP 443. Complete HTTP request lines on 80/8080/8880 are dispatched immediately; the two-second inspection allowance remains only for incomplete or unusual payloads. The TLS idle fallback can be tuned with `-sniff-timeout`.

Hysteria 1 account creation displays the named account and import link. The password is the Hysteria 1 authentication string; use the saved link for the selected account. Account menu option 5 retrieves saved links.

For UDP Custom, test IPv4 and public UDP 5300 with an SSH username/password. Ports 53/443/1194/4000 and ranges 6000–50000 are dedicated to other protocols. Run `bash ./udp-routing-audit.sh 5300` for service, listener, routing and recent gateway logs. This does not verify a client connection or provider firewall access.
