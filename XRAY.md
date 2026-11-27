# Xray in ENG

ENG runs its own pinned Xray-core v26.10.31 binary and `frimps-xray.service`.
It does not replace a separately installed `xray` service. HTTP and REALITY
listeners bind to loopback; the existing ENG gateway owns ports 80/443.
Native Shadowsocks uses its own public TCP listener after an account is created.

| Protocol | Transport | Direct NTLS | TLS | Path |
|---|---|---|---|---|
| VLESS | WebSocket | 80 | 443 | `/vless-ws` |
| VLESS | HTTPUpgrade | 80 | 443 | `/vless-upgrade` |
| VLESS | XHTTP | 80 | 443 | `/vless-xhttp` |
| VMess | WebSocket | 80 | 443 | `/vmess-ws` |
| VMess | HTTPUpgrade | 80 | 443 | `/vmess-upgrade` |
| Trojan | WebSocket | not exported | 443 | `/trojan-ws` |
| VLESS | TCP + REALITY + Vision | — | 443 | no HTTP path |
| VLESS | gRPC | — | 443 | service `vless-grpc` |
| VMess | gRPC | — | 443 | service `vmess-grpc` |
| Trojan | gRPC | — | 443 | service `trojan-grpc` |
| Shadowsocks 2022 | native TCP | 8388 | no outer TLS | no HTTP path |

gRPC uses HTTP/2, ALPN `h2` and nginx `grpc_pass`. Its service-name prefixes
are separate from existing WebSocket/XHTTP/OpenVPN paths. No gRPC NTLS links
are exported. XHTTP remains the preferred newer HTTP transport; gRPC is an
additional compatibility option.

Shadowsocks uses `2022-blake3-aes-128-gcm`, a persistent server key and a separate
random key per account. Its `ss://` link includes both keys in the standard
`ServerKey:UserKey` password format. TCP 8388 must be allowed in provider/host
firewalls and use a DNS-only/direct hostname. It cannot use Cloudflare's ordinary
HTTP proxy. No native UDP listener or UDP firewall range is added. With no active
Shadowsocks accounts, the listener is omitted to prevent single-user server-key
fallback after the last account expires or is deleted.

The port-80 modes have no outer TLS. Ordinary VLESS NTLS has no encryption;
VMess uses its own protocol encryption. Prefer TLS or REALITY when possible.
Transport availability is not a guarantee of carrier/CDN compatibility or
permission to carry traffic under a provider's terms.

## Existing VPS update

Run from the updated ENG checkout after backing up managed state:

```bash
cd /root/eng &&
git pull --ff-only origin main &&
bash ./xray-install.sh &&
bash ./refresh-menu-v6.sh &&
bash ./xray-audit.sh
```

These commands stop if installation fails. After a successful Xray audit, run
`bash ./protocol-health-v6.sh --live` to check the other protocols too. A menu
refresh alone does not install an absent Xray service.

The installer requires ENG's existing Go, Python, curl, jq, unzip, HAProxy and
nginx prerequisites. It verifies the pinned release archive SHA256 before
installing. Existing connections through the payload gateway disconnect once
while its updated binary is restarted. Xray itself starts with **no accounts**;
there is no default/test user or password.

Fresh `install-frimps.sh` installations perform the same installation and
require Xray and its expiry timer to be active and enabled at completion.

For a separate direct NTLS hostname on first installation:

```bash
bash ./xray-install.sh --domain direct.example.com --reality-domain reality.example.com
```

Create DNS-only A records (and AAAA only if this VPS has working IPv6) for these
names pointing to this VPS. The default direct hostname is ENG's existing primary
domain, and fresh installations use that existing direct hostname as the REALITY
address too. A separate REALITY subdomain is optional and needs its own DNS-only
record; installation does not create it. TLS links
use ENG's existing primary domain and certificate, even if the NTLS alias differs.
Use DNS-only for the TLS hostname too when you want direct TLS connections.
The installer does not create or change DNS records or Cloudflare settings.
Repeated installation preserves settings, REALITY keys, short ID and accounts.
An explicit `--reality-domain` on reinstall updates only the exported connection
address. To change that address without reinstalling or restarting services:

```bash
bash ./xray-accounts.sh reality-address --reality-domain fr.vpnguruz.store
```

Re-export the VLESS link afterward. Existing installations keep their previously
selected address until explicitly changed. If an old `reality.YOUR_DOMAIN` name
has no DNS record, set the address to an existing DNS-only hostname or create the
missing record. In a client, edit the connection address while preserving the
exported SNI, public key, short ID and Vision flow. A different address does not
require changing those authentication settings.

REALITY's address and SNI are different: the address is your DNS-only hostname;
the default SNI/target is `www.apple.com:443`. HAProxy selects REALITY using
that target SNI, **not** your DNS alias, because the alias is not sent in the TLS
ClientHello. Other SNI values retain the existing TLS multiplexer route.

## Accounts and Gen

Open menu option 7, Xray Account Management. Choose VLESS, VMess, Trojan or Shadowsocks;
create, renew, delete, list and export links are available. Numeric names are
supported, and existing account selection uses numbered lists with 0/00 Back.
Each protocol has its own accounts. Renewal keeps its UUID/password/key. Deletion
and expiry remove it from Xray; they do not delete SSH accounts. Account updates
restart Xray and disconnect its existing sessions. Expiry dates are inclusive
UTC dates; the persistent timer cleans expired accounts at 00:01 UTC daily.

CLI equivalents:

```bash
bash ./xray-accounts.sh create vless eddy 30
bash ./xray-accounts.sh links vless eddy
bash ./xray-accounts.sh renew vless eddy 60
bash ./xray-accounts.sh list vmess
bash ./xray-accounts.sh delete trojan eddy
bash ./xray-accounts.sh create shadowsocks eddy 30
bash ./xray-accounts.sh links shadowsocks eddy
```

Each exported link is displayed in its own labeled block with a blank line
between blocks. Copy the URI line into the client or Gen; whitespace is never
inserted inside the URI. Exported links contain private UUIDs/passwords/keys.
For VLESS, VMess and Trojan, put the appropriate link into
the Gen's existing V2Ray port-80 or port-443 server field. Each field holds one
chosen configuration, so separate server entries can expose different transports.
All four checked apps already have HTTPUpgrade/XHTTP parsing and configuration;
their Gens preserve these server-link fields. No SSH certificate bundle changes
are required; Xray accounts authenticate separately.

Use SS-aware app and Gen builds for Shadowsocks templates. The TG/GT/GV/VC
Desktop source pairs were aligned on 2026-11-27; older builds may still reject
`ss://` in standard templates. Put the link in `V2ray80` and use a direct-host
`@80` standard tweak with Reverse/Dual off. The slot selects the stored profile;
the actual TCP port (8388 by default) is retained. Native Shadowsocks does not
use SNI/HTTP Host overrides or Google Cloud TLS mode. These Android source
changes require separate app/Gen release builds and phone verification; ENG
installation alone does not update an installed Android app.

On the first Xray install, `--shadowsocks-port 8388` can choose another unused TCP
port above 1023. Subsequent installs preserve that selection, its server key and
every existing account. Run `xray-install.sh` for this upgrade so the gRPC nginx
locations, normalized account store and Shadowsocks settings are all installed.

## Preservation and verification

Installation overlays only managed Xray routes into the live gateway files. It
does not regenerate SSH units or change the selected SSH target. Existing SSH,
OpenVPN, BHTTP, HCR and UDP configurations remain in place. No SlowDNS domain,
key, MTU, backend, certificate-account policy or firewall range is changed.
Future routing renders reapply the Xray overlay when settings exist.

Touched deployment files are backed up under `/var/backups/frimps-v6/xray-*`;
deployment failures restore those files and attempt to recover prior services.
Account configuration changes are validated with the real core before replacing
the live account/config files; failed restarts restore their previous contents.

`xray-audit.sh` checks core configuration, loopback listeners, gateway syntax,
boot enablement and the expiry timer. It does not claim successful client login
or browsing. Test each advertised link on a live VPS, including XHTTP over
negotiated HTTP/2, REALITY target reachability, reconnects and existing protocols.
Cloudflare proxy tests are separate from the direct DNS-only deployment.

Real Xray v26.10.31 and nginx 1.26.3 loopback tests authenticate and transfer data
twice through all 16 advertised combinations, plus a second independent
Shadowsocks identity (34 sessions), including gRPC/TLS and XHTTP/TLS over HTTP/2,
REALITY/Vision and native Shadowsocks 2022. TLS tests use
an explicitly pinned temporary certificate and the exported Chrome fingerprint.
Fresh/upgrade/rollback shell tests use private filesystem fixtures and simulated
systemd commands; Linux permissions, actual boot ordering and provider networking
still require live VPS verification. App/Gen checks were source inspections;
no Android binaries were changed or rebuilt for this server change.
