# Opt-in upstream DNSTT + SSH comparison

This path is separate from `install-frimps.sh`, `slowdns-install.sh` and the
ePro binary updater. No default backend changes. It installs no SlipGate
manager, SOCKS server, DNS router, Xray, Reality or VayDNS.

## Which implementation

`upstream-20260501` selects David Fifield's DNSTT tag `v1.20260501.0`, revision
`0c5c52a57d899c05428c116898941761a2ed83c2`. Source and vendored dependencies
are bundled in `dnstt-source/upstream-20260501.tar.gz`, with an archive SHA-256
in `dnstt-source/pin.json` and a per-file manifest inside the archive. The build
uses vendored dependencies with toolchain downloads and module proxies disabled.
It records compiler version, target, source pin and executable hashes in
`build.json`. It does not execute an upstream installer.

Provenance limitation: the public upstream snapshot was imported from the
user-supplied TG source archive, with Windows CRLF/CRCRLF normalized to LF.
The declared upstream revision was confirmed on the upstream commit page;
the entire tree could not be fetched independently because this workstation's
direct GitHub access failed. The checked hashes identify the actual inputs,
not a publisher signature. DNSTT is CC0; third-party dependency licenses are
retained in the bundled `vendor` tree. No AGPL SlipNet/SlipGate code was copied.

Primary references reviewed:

- https://repo.or.cz/dnstt.git/commit/0c5c52a57d899c05428c116898941761a2ed83c2
- https://www.bamsoftware.com/software/dnstt/protocol.html
- https://github.com/anonvector/SlipNet/tree/2ed00fd0072ad0b558e30ec6b5e8b30948f98894
- https://github.com/anonvector/slipgate/tree/e1df982e109a4a14bae75eb42e0d5cbfb84c0695

SlipNet documents UDP/DoH/DoT and DNSTT + SSH. SlipGate distinguishes SSH
forwarding from its SOCKS backend and has a separate DNS router. Its current
DNSTT/NoizDNS combination and inaccessible mobile submodule were not assumed
to be TG-compatible. This comparison instead uses a pinned upstream TXT/KCP/
Noise/smux implementation, with real encrypted transport tests. CLI option
similarity is not the compatibility gate.

## Build without changing services

Requires Python 3.9+, an explicitly available Go 1.21+ toolchain and sufficient
disk/RAM for compilation. Debian 12's stock Go 1.19 is too old. No compiler or
system package is installed automatically. Go 1.27.1 was used in local checks.

```bash
python3 ./dnstt-build.py --implementation upstream-20260501 \
  --go /opt/go/bin/go --target linux-amd64 \
  --output /var/cache/frimps-dnstt/upstream-20260501
```

Use `linux-arm64` for an ARM64 VPS. `host` builds runnable host binaries for
local tests. Windows builds append `.exe`. The default build runs upstream
host tests before cross-compiling. `--skip-tests` is explicit and recorded.
Keep the source bundle and pin next to the script when copying files manually.

## Record production, then stage an isolated SSH candidate

From the ENG repository as root on Linux, with systemd, iproute2, OpenSSL and
an existing local SSH server:

```bash
bash ./dnstt-ssh.sh audit
bash ./dnstt-ssh.sh stage --implementation upstream-20260501 --backend ssh \
  --build /var/cache/frimps-dnstt/upstream-20260501
```

Defaults:

- New unit `frimps-dnstt-ssh-test.service`, files in `/opt/frimps-dnstt-ssh-test`.
- **Loopback UDP 127.0.0.1:15353**, independent of production UDP 53.
- Copy and cryptographically validate the existing SlowDNS key pair; never
  rotate production identity. Read the existing nameserver from ENG state.
- Forward raw tunnel streams to **OpenSSH 127.0.0.1:22**. `--ssh-backend gateway`
  explicitly selects the existing dedicated SSH backend on 127.0.0.1:2222.
- DNS response limit 1232 for the candidate. No production MTU changes.
- Start the test service but do not enable a newly created one for boot unless
  `--enable` is passed. A previously enabled test service keeps that state.

Staging verifies source/artifact hashes, key correspondence and an encrypted
local DNSTT-to-SSH banner before changing test files, then repeats the stream
test through the installed test service. This is not an SSH password login or
internet test. It prints readiness and first verified stream timings.

`--identity fresh --domain test.example.org` creates/preserves a separate test
identity. It cannot be activated over production with a different public key.

For an external TG test **without production activation**, use an isolated VPS
or another assigned IP whose UDP 53 is free:

```bash
bash ./dnstt-ssh.sh stage --implementation upstream-20260501 --backend ssh \
  --build /var/cache/frimps-dnstt/upstream-20260501 \
  --identity fresh --domain test.example.org --listen 192.0.2.10:53
```

Replace the example address/domain. An occupied or unidentified UDP listener
aborts; the installer never stops a competing service. Other public UDP ports
are deliberately avoided because ENG allocates them to existing protocols.
This is port ownership protection, not a carrier reachability restriction.
No host/provider firewall rules, DNS records or NAT rules are changed.
The loopback default is not directly reachable from a phone or public resolver.

## DNS and public resolver tests

Delegate the **test** zone to a DNS-only nameserver hostname whose A/AAAA
records reach the selected candidate listener. Do not point a production zone
at the candidate before choosing that change. `audit` prints the candidate's
public key, listener ownership, binary hash, actual unit, recent logs and
parent NS/A/AAAA answers. When production exists it also runs ENG's existing
SlowDNS audit. Resolver or delegation failures are diagnostic findings; there
is no public-internet/VALIDATED requirement on connection entry.

The normal path is:

```text
TG -- UDP, HTTPS or TLS --> recursive resolver -- DNS/UDP 53 --> DNSTT -- raw TCP --> SSH
```

DoH/DoT TLS ends at the recursive resolver. Opening authoritative VPS ports
443/853, adding a website certificate, or changing the SSH account model is
not needed for this path. This candidate does not add SlipGate's TCP/53 router
or its protocol extensions; a resolver path requiring authoritative TCP
fallback needs separate investigation.

After delegation points to the intended listener, explicitly probe a selected
path with the built native client (on a Linux test host or VPS):

```bash
python3 ./dnstt-probe.py --client /opt/frimps-dnstt-ssh-test/dnstt-client \
  --keys /opt/frimps-dnstt-ssh-test --domain test.example.org \
  --transport udp --resolver 8.8.8.8:53 --timeout 45

python3 ./dnstt-probe.py --client /opt/frimps-dnstt-ssh-test/dnstt-client \
  --keys /opt/frimps-dnstt-ssh-test --domain test.example.org \
  --transport doh --resolver https://dns.google/dns-query --timeout 60

python3 ./dnstt-probe.py --client /opt/frimps-dnstt-ssh-test/dnstt-client \
  --keys /opt/frimps-dnstt-ssh-test --domain test.example.org \
  --transport dot --resolver dns.google:853 --timeout 60
```

These are optional tests, not mandatory calibration or country/network gates.
The timeout is only the diagnostic limit; it is not added to app startup.
The probe never changes resolver settings or disables certificate validation.
An SSH banner verifies an encrypted stream to the SSH backend, not account
authentication, VPN routes, browsing, speed or every TG native engine.

## Explicit production activation and rollback

Only after the candidate comparison succeeds and the operator chooses it:

```bash
bash ./dnstt-ssh.sh activate --implementation upstream-20260501 --backend ssh
```

This command requires the staged domain/public key to match production,
rechecks the artifact, and tests the production key and raw SSH backend through
a private candidate process. It refuses unknown ExecStart overrides. It saves
the current executable, unit, backend record, active/enabled flags and hashable
file contents, then replaces **only** the production server executable. The
unit/domain/SSH target/MTU settings remain intact. SSH users, other protocols,
production keys, certificate files and firewall policy are not rewritten.
It restarts only SlowDNS, checks the actual listener/key/backend, then probes
an encrypted SSH stream through the production listener. Failed activation
restores previous files and service state.

Every stage/activation prints an exact rollback command:

```bash
bash ./dnstt-ssh.sh rollback /var/backups/frimps-v6/dnstt/EXACT-BACKUP
```

Backups are root-private. Rollback refuses paths outside its backup root and
unexpected manifest destinations, and verifies saved file checksums before
stopping any service. A first-stage rollback removes created test
files and leaves production alone. Roll back multiple changes in reverse
order; do not mix this and ePro activation without recording each backup.
The baseline SlowDNS installer and ePro updater share the production executable
slot. Rerunning either can replace this selected candidate; inspect the actual
executable hash rather than relying on a stale backend record.

## Validation limits

### Live acceptance status (2026-11-13)

The operator built the pinned source on Debian 12 amd64 with Go 1.27.4,
staged the isolated service, and explicitly activated it on the test VPS.
Staging and activation passed encrypted SSH-banner probes. Production
domain, keys, unit, MTU and SSH accounts were preserved. TG and SlipNet
connected over UDP; SlipNet browsing was confirmed.

The companion chat, **Audit VPN apps and AdMob parity**, reports TG traffic
probes passing with Google DoH/DoT and Cloudflare DoH/DoT. Cloudflare
recovery checks passed after Wi-Fi cycles with mobile fallback available.
These are selected-path results, not a guarantee for every carrier.

VayDNS clients also passed selected tests with **DNSTT compatibility enabled**.
This does not install a VayDNS server or support its compatibility-OFF wire
protocol. The same DNSTT nameserver, public key and SSH credentials apply.
TG/Gen's new-profile engine default is a client setting and does not change
ENG's server implementation. VayDNS DoH was slower in the reported samples.

Still pending: 15–30 minute sessions, the earlier connected-but-stalled
condition, recovery after a complete network outage without mobile fallback,
and sustained browser/media tests. Keep this upgrade opt-in until those pass.
No new fresh-install default or independent VayDNS service is introduced.

### Local validation

Local checks performed on Windows using source-built host binaries:

- Upstream DNS/client/Noise tests passed.
- Real UDP DNSTT encrypted stream round-trip: 32799 bytes.
- Real DoH and DoT DNSTT streams through local TLS resolver fixtures: 9600
  bytes each. Fixture certificates were verified using an explicit test CA;
  no system trust-store change or certificate bypass was used.
- Linux amd64 server/client cross-build succeeded. Linux execution/systemd
  lifecycle and actual VPS firewall behavior were not tested here.
- Installer tests cover listener conflicts, raw SSH selection, source pins,
  identity protection and rollback after simulated stage/activation failure.

Explicit integration-test commands:

```text
python dnstt-probe.py --server HOST_SERVER --client HOST_CLIENT
python tests/dnstt_transport_smoke.py --go GO_EXECUTABLE --server HOST_SERVER
```

The TLS fixture tests add a temporary Go test file to an unpacked source tree;
they do not change the source archive or the distributed executables. Public
resolver tests and Android comparisons are reported above separately from
these local checks. Those live results do not verify every app build or
resolver path; this installer cannot enable Android transports.
