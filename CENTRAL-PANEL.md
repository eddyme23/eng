# Central ENG management

One central panel can manage its own ENG VPS and up to **16 remote ENG VPSs**.
Each remote agent connects outward over verified HTTPS. VPN accounts stay on the
selected server. Pairing does not copy SSH/certificate/UDP accounts or authorize
them on a proxy VPS. Existing local panels and terminal menus remain usable.

## 1. Configure VPS A (81.17.97.202)

Your DNS record should be:

| Type | Name | Address | Proxy | TTL |
|---|---|---|---|---|
| A | panel.vpnguruz.store | 81.17.97.202 | DNS only | Auto |

On A, where ENG is already installed:

```bash
cd /root/eng
git pull --ff-only origin main
bash ./panel-install.sh --central --domain panel.vpnguruz.store --local-name France --issue-certificate
```

The installer reuses the existing panel administrator login if present. On a
first installation it asks for a panel username and password. Central management
also requires an authenticator account: add the displayed setup key to an
authenticator app, then enter its current six-digit code to finish setup. Keep
the setup key private. Accurate server and phone time are required.

The optional certificate flag issues a missing certificate using the **existing**
ENG certbot installation, Let's Encrypt account and root-only Cloudflare DNS
credentials at `/etc/letsencrypt/cloudflare.ini`. It does not request another API
token or change the primary VPN domain. If those credentials are unavailable,
provide a valid certificate under `/etc/letsencrypt/live/panel.vpnguruz.store/`
before running the installer without `--issue-certificate`. Certbot's existing
deployment hooks may run during certificate issuance.

Open:

**https://panel.vpnguruz.store:8445**

Allow inbound TCP 8445 on A for your browser and for B/C's outgoing connections.
If you restrict it to IP addresses, include the remote VPS addresses as well as
your administrator address. A's existing VPN gateways on 80/443 stay in place;
the first central version keeps the panel's separate HTTPS port. A saved custom
panel port is preserved, and the installer prints the actual URL.

The server selector includes **France · this VPS** automatically. Do not install
an agent on A just to manage A itself.

## 2. Add B or C

In the central panel:

1. Open **Add another VPS**.
2. Enter a name such as **USA** or **Germany**.
3. Click **Generate pairing code**.
4. Copy the private, single-use code from the results area. It expires in 15 minutes.

On that target VPS (ENG must already be installed):

```bash
cd /root/eng
git pull --ff-only origin main
bash ./panel-agent-install.sh --central https://panel.vpnguruz.store:8445
```

Enter the pairing code when prompted. It is hidden during entry and is not
passed as a command-line argument. The VPS receives unique revocable agent
credentials. No inbound management port or public web service is installed by
this command; only the local Unix-socket helper and outbound agent are enabled.
An existing individual panel can remain running.

Return to the central panel and click **Refresh servers**. Select the target VPS
before any account operation. Labels show ready, busy/reconnecting or offline.
Status is a connectivity snapshot, not a VPN browsing test. If a server is offline
or busy, the operation fails clearly; it does not fall back to A or queue work
for later. Refresh and retry when it is ready.

## 3. Account operations and exports

The existing SSH password/certificate selector and all other protocol sections
apply to the selected VPS. Delete/export confirmations and operation messages
identify the target server. The central machine does not rewrite the other
servers' account stores. Credential exports pass through HTTPS and are held in
memory for display; they are not stored in the central registry database.

Agent commands use the existing restricted helper, not a remote shell. Requests
have unique identifiers. The central panel does not resend delivered operations;
the agent also writes a durable duplicate-request marker before execution. If a
connection fails after delivery, the panel reports that the operation **may have
executed**. Inspect the account before submitting another operation. This avoids
silently creating/renewing/deleting it twice. An already delivered command cannot
be cancelled by signing out or removing the server.

## 4. Remove a server or update

Select a remote VPS and choose **Remove server access**. This revokes that agent's
credentials centrally; it does not delete VPN accounts or stop VPN services. The
agent stops when it next receives an authentication rejection. Local access to
that VPS remains available. To pair it again, generate a new code and use:

```bash
bash ./panel-agent-install.sh --central https://panel.vpnguruz.store:8445 --re-pair
```

Finish any in-progress account operation before updating the panel or an agent.
For updates, pull ENG first, then:

```bash
# Central A: preserves hostname, login, authenticator and paired registrations
bash ./panel-install.sh

# Each agent B/C: preserves its current pairing, no new code required
bash ./panel-agent-install.sh
```

To replace a lost authenticator from a trusted root terminal on A:

```bash
bash ./panel-install.sh --reset-2fa
```

This prints a new setup key and verifies a current code. Password reset remains
`bash ./panel-install.sh --reset-password`; it does not disable the authenticator.

## State and diagnostics

* Central registry: `/var/lib/frimps-panel/central.sqlite` (hashed pairing codes
  and agent tokens, labels, revocations and used authenticator counters).
* Central login/authenticator configuration: `/etc/frimps-panel/web.json`.
* Remote agent credential: `/etc/frimps-panel-agent/config.json` (root-owned,
  readable only by the service group).
* Remote replay ledger: `/var/lib/frimps-agent/jobs.sqlite` (request identifiers,
  operation-type digests and completion markers; no account names, credential
  output or passwords).

Protect backups containing these files. Do not clone an agent configuration or
reuse one registration across multiple VPSs. Restarting A loses pending in-memory
commands but retains registrations. Agents reconnect automatically. A's outage
does not stop VPN services on any server.

```bash
# A
systemctl status frimps-panel frimps-panel-helper --no-pager
journalctl -u frimps-panel --no-pager -n 60
# B/C
systemctl status frimps-panel-agent frimps-panel-helper --no-pager
journalctl -u frimps-panel-agent --no-pager -n 60
```

The central administrator can manage accounts on every paired server. This first
release has one administrator, required authenticator login, no reseller roles,
no arbitrary remote shell and no automatic cross-server account replication.

## Verification boundary

Local tests cover real HTTPS pairing and command/result exchange, certificate
verification, administrator two-factor login, CSRF separation, target isolation,
revocation, one-use/expired codes, offline behavior, restart state and duplicate
requests. Account execution is substituted during these tests. Debian systemd
startup/reboot, certbot issuance/renewal, real account operations and phone
connections must still be verified on staging VPSs before production rollout.
