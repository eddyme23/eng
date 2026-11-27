# Xray in ENG

ENG runs its own pinned Xray-core v26.10.31 binary and `frimps-xray.service`.
It does not replace a separately installed `xray` service. All seven Xray
listeners bind to loopback; the existing ENG gateway owns public ports.

| Protocol | Transport | Direct NTLS | TLS | Path |
|---|---|---|---|---|
| VLESS | WebSocket | 80 | 443 | `/vless-ws` |
| VLESS | HTTPUpgrade | 80 | 443 | `/vless-upgrade` |
| VLESS | XHTTP | 80 | 443 | `/vless-xhttp` |
| VMess | WebSocket | 80 | 443 | `/vmess-ws` |
| VMess | HTTPUpgrade | 80 | 443 | `/vmess-upgrade` |
| Trojan | WebSocket | not exported | 443 | `/trojan-ws` |
| VLESS | TCP + REALITY + Vision | — | 443 | no HTTP path |

The port-80 modes have no outer TLS. Ordinary VLESS NTLS has no encryption;
VMess uses its own protocol encryption. Prefer TLS or REALITY when possible.
Transport availability is not a guarantee of carrier/CDN compatibility or
permission to carry traffic under a provider's terms.

## Existing VPS update

Run from the updated ENG checkout after backing up managed state:

```bash
cd /root/eng
git pull --ff-only origin main
bash ./xray-install.sh
bash ./refresh-menu-v6.sh
bash ./xray-audit.sh
bash ./protocol-health-v6.sh --live
```

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
domain, and the default REALITY address is `reality.PRIMARY_DOMAIN`. TLS links
use ENG's existing primary domain and certificate, even if the NTLS alias differs.
Use DNS-only for the TLS hostname too when you want direct TLS connections.
The installer does not create or change DNS records or Cloudflare settings.
Repeated installation preserves settings, REALITY keys, short ID and accounts.

REALITY's address and SNI are different: the address is your DNS-only hostname;
the default SNI/target is `www.apple.com:443`. HAProxy selects REALITY using
that target SNI, **not** your DNS alias, because the alias is not sent in the TLS
ClientHello. Other SNI values retain the existing TLS multiplexer route.

## Accounts and Gen

Open menu option 13, Xray Account Management. Choose VLESS, VMess or Trojan;
create, renew, delete, list and export links are available. Numeric names are
supported, and existing account selection uses numbered lists with 0/00 Back.
Each protocol has its own accounts. Renewal keeps its UUID/password. Deletion
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
```

Exported links contain private UUIDs/passwords. Put the appropriate link into
the Gen's existing V2Ray port-80 or port-443 server field. Each field holds one
chosen configuration, so separate server entries can expose different transports.
All four checked apps already have HTTPUpgrade/XHTTP parsing and configuration;
their Gens preserve these server-link fields. No SSH certificate bundle changes
are required; Xray accounts authenticate separately.

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

Local validation for this change: 20 Xray tests and 19 existing routing, menu,
health and firewall tests passed, together with the payloadgate, tlsmux and
sshws Go test packages. Real Xray v26.10.31 and nginx 1.26.3 loopback tests
authenticated and transferred data twice through all 12 advertised combinations
(24 sessions), including XHTTP/TLS over HTTP/2 and REALITY/Vision. TLS tests used
an explicitly pinned temporary certificate and the exported Chrome fingerprint.
Fresh/upgrade/rollback shell tests use private filesystem fixtures and simulated
systemd commands; Linux permissions, actual boot ordering and provider networking
still require live VPS verification. App/Gen checks were source inspections;
no Android binaries were changed or rebuilt for this server change.
