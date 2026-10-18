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

BHTTP restarts now stop the alternate-port socket and its active proxy together before restarting the backend and reopening the socket. This avoids rebinding port 8180 while the proxy still holds it. Apply with `bash ./refresh-menu-v6.sh`, then `bash ./restart-bhttp.sh`. Service controls 9 (HCR) and 10 (BHTTP) use the maintained restart actions; their submenus accept padded option numbers. A socket-activated proxy may be inactive before the first client connection.

HCR and BHTTP no longer have separate installer submenus under Service Controls. They are included in Restart SSH services and Restart all, shown in service status, and available under View protocol logs (HCR NTLS/TLS and BHTTP). Fresh installation continues to install both by default.

### AIO-style SSH connection handling

Run `bash ./apply-aio-ssh-fixes.sh` on an installed server to rebuild gateways and move SlowDNS to existing OpenSSH on loopback TCP 22. This disconnects SSH/payload and SlowDNS sessions; it does not change administrative SSH configuration, accounts or host keys. Fresh SlowDNS installs use OpenSSH 22.

Legacy HTTP payload connections receive 101/200 first, then must send `SSH-` identification within 30 seconds before a Dropbear connection is opened. HTTP-only clients do not consume Dropbear pending-authentication slots. Standard WebSocket and OpenVPN routing remain separate. Clients waiting for a server SSH banner before sending their identification are not compatible with this legacy deferred path; SSL Direct retains its existing fallback. Gateway relay endpoints close together on disconnect. Dropbear's authentication limits remain unchanged, so repeated actual SSH login attempts can still exhaust them.

TLS HTTP/1 payloads now go directly from tlsmux to payloadgate on loopback 3102. Nginx reverse-proxy upgrade handling could return 101 yet fail to tunnel a legacy request lacking the Upgrade header. Direct routing supports those raw legacy payloads as well as standard WebSocket and `/openvpn`; HTTP/2 retains its separate Nginx route. Apply with `bash ./apply-aio-ssh-fixes.sh` (or `apply-connection-fixes.sh` if SlowDNS was already migrated). Gateway unit validation now requires the direct HTTP/1 target. TLS routing/relay integration tests can run with `ENG_RUN_TLS_INTEGRATION=1`, Go and OpenSSL available.

For a controlled capacity test on an affected VPS, run `bash ./apply-ssh-capacity-fix.sh`. This creates a dedicated OpenSSH instance on 127.0.0.1:2222, with a 30-second login grace time and MaxStartups 100:30:300, then selects it for TLS Direct, payload and WebSocket gateways using named systemd overrides. It reuses existing OpenSSH host keys and account authentication, does not edit administrative SSH configuration or HCR/BHTTP targets, and keeps the fresh-install default unchanged. It validates configuration and the SSH banner before switching gateways. Root login is disabled on this dedicated backend. Existing gateway sessions disconnect and client host-key prompts may change. Roll back with `bash ./apply-ssh-capacity-fix.sh --rollback`. Script/transport tests do not replace real PAM/password, expiry and browsing checks on Debian.

Fresh installations automatically select the dedicated loopback OpenSSH backend on
127.0.0.1:2222 for SSH payload, WebSocket, and TLS gateways. Administrative SSH
on port 22 is unchanged. The backend is enabled at boot and checked before the
installer reports success. Existing installations can use
`bash ./apply-ssh-capacity-fix.sh`; rollback remains available with `--rollback`.

All protocol services are installed and enabled at boot by the fresh installer
(HCR/BHTTP can still be explicitly skipped with their V6_INSTALL_* options).
Startup failures now stop setup instead of printing a successful enable message.
The BHTTP alternate proxy starts on demand through its enabled socket; account
cleanup and certificate renewal run through enabled timers. These worker services
are not expected to run continuously. Menu choices accept 0/00 for Back (Exit at
the main menu), and padded choices such as 01 and 08 are accepted throughout.

SlowDNS audit: `bash ./slowdns-audit.sh` checks boot state, UDP 53 ownership,
matching DNS keys, the OpenSSH 22 banner, and public NS/A records. `--local`
skips public DNS queries. Delegate the tunnel domain (V6_SLOWDNS_NS) with an NS
record to a DNS-only hostname whose A record is the VPS public IPv4; the
installer does not create these DNS records. Permit inbound UDP 53 at the host
and provider firewall. Use an existing SSH account and the displayed DNS public
key. An active service alone does not establish a working client connection.
Fresh SlowDNS installs now generate a unique key pair. Existing pairs are kept
on reinstall, including legacy keys, so clients are not silently invalidated.
To apply SlowDNS-only installation fixes: `bash ./slowdns-install.sh` (disconnects
SlowDNS sessions), then `bash ./refresh-menu-v6.sh` and `bash ./slowdns-audit.sh`.
The managed backup now includes /etc/slowdns.

For SlowDNS connections without browsing, run
`bash ./slowdns-flow-audit.sh USERNAME` during a reconnect and browsing attempt.
This read-only report includes the actual listener/command, a local DNS error
response probe, account expiry/lock state, per-account OpenSSH forwarding policy,
current-boot authentication events, complete firewall rules and host HTTPS access.
The local probe uses an intentionally invalid tunnel name; a DNS error response
is expected and does not establish an encrypted client session. A UDP 53 exception
in the Frimps NAT table alone does not prove other NAT/filter tables permit traffic.
