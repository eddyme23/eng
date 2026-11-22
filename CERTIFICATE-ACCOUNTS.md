# Certificate accounts for TG / Gen

ENG supports two independent account types: existing username/password accounts,
and operator-generated OpenSSH certificate accounts. No enrollment endpoint,
access code, Google Cloud credentials, or Play Integrity is involved.

## VPS usage

Update the checkout and run `bash ./refresh-menu-v6.sh`. In the menu select
SSH Account Management -> App certificate accounts -> Create certificate account. Choose a NEW account name and validity (1-3650 days).

Equivalent commands:

```bash
bash ./certificate-accounts.sh create customer1 365
bash ./certificate-accounts.sh renew customer1 365
bash ./app-ssh-auth.sh bundle-export customer1
bash ./app-ssh-auth.sh revoke customer1 certificate-account
```

Creation generates a random, undisclosed OS password, signs a fresh P-256 key,
and applies certificate-only SSH policy to that account. A separate generated
UDP Custom password is included privately in its JSON; SSH password login remains
disabled. UDP Custom still uses password authentication underneath. Other accounts retain
password access. On failure no bundle is issued; remove the new account through
SSH Account Management before retrying. Do not reuse an existing password account
with the low-level `bundle-create` command: it explicitly converts that account.

The private JSON is saved to `/etc/frimps-app-auth/bundle-customer1.json` (root
only, mode 0600 inside mode 0700 directory). Transfer it securely to Gen. Export
prints the private credential deliberately; do not paste it in public logs.
Renewal extends the OS account, re-signs its same key and updates this file.
Import the replacement in Gen and redistribute the updated configuration.
Certificate validity is capped by OS account expiry at midnight UTC. Renewal
of an unexpired account extends its existing expiry; certificate lifetime starts
at renewal time. Revocation locks the account password (including UDP Custom), removes certificate
trust and the local bundle, and does
not disconnect authenticated sessions. Account deletion uses the existing purge.
Older renewed certificates remain valid until expiry or account revocation.

## App / Gen handoff

The menu also offers **Import existing certificate JSON** and **Show certificate
connection details**. Create/renew/import print the applicable endpoint details,
payloads and DNSTT nameserver/key without printing private credentials.

For import, choose a NEW account name and validity, paste the complete ENG JSON,
then type `END` on its own line. ENG verifies its private/public key match and
reuses that key, but always issues a NEW locally trusted certificate. The old
certificate, CA, username, expiry and UDP password are not adopted. This does not
automatically trust foreign certificate authorities. Use the newly exported JSON
for this VPS. Only complete P-256 ENG bundles are accepted, not arbitrary TLS
certificates or public certificates without a private key. The low-level command
`bash ./app-ssh-auth.sh bundle-import ACCOUNT --days DAYS` supports an existing
managed SSH identity and explicitly converts it to certificate-only SSH login.

## UDP Custom account integration

New JSON includes `udpCustom` with `authMethod: "password"`, `username`, `password`
and `portRange: "50001-65535"`. The private generated secret is stored only inside
the root-only bundle; Linux stores its SHA-512 password hash. The ordinary account
listing and connection-details output never print it. Renewal preserves it;
renewing an older bundle adds it. Revocation prevents new password authentication
as well as new certificate authentication. Existing UDP sessions may persist.

App/Gen must carry this nested object in the protected config and pass these
credentials to the existing UDP Custom engine. No manual username/password entry
is needed. This is NOT certificate authentication on the UDP wire. Do not send
SSH certificates to the password-only UDP backend or derive a password from a
public certificate. Live UDP connection, expiry and revocation tests remain
required on the deployed upstream binary. The app's current engine can send
username/password, but config wiring must be implemented in the app chat.

Add a second authentication choice, **Certificate account**, alongside **Username
and password**. Import this schema; do not send it through the existing
phone-generated nonexportable-key/device-certificate importer:

- `schema`: 1, `type`: `eng-ssh-account-bundle`
- `authMethod`: `openssh-user-certificate`
- `username`: internal SSH identity; users need not enter it separately
- `privateKeyIncluded`: true; `privateKey`: PEM/OpenSSH P-256 private key
- `publicKey`, `certificate`, `caPublicKey`, `caFingerprint`
- `deviceId`, `deviceLabel`, `validAfter`, `validBefore`
- `genPolicy.SSHAuthMethod`: `account_certificate`
- `genPolicy.SSHCertificateCA`, `genPolicy.SSHHostKeyPin`: SHA256 pins

Gen must protect the whole credential when exporting configs and avoid logging
it. The app must validate key/certificate correspondence, CA signature, principal,
expiry and server host-key pin, then sign SSH authentication with the imported
private key and present the user certificate. Keep certificate-only mode fail
closed: never silently fall back to a password. Imported software keys require a
separate app credential store; they are not Android-generated Keystore keys.
ENG does not modify app or Gen code. Their importer/authentication changes and
an end-to-end app test are required before this mode can be used.

Supported paths: SSH, SSH WebSocket, SSL Direct, SSL WebSocket, BHTTP, HCR plain/
TLS, and SlowDNS/DNSTT through their configured OpenSSH backend. The transport
itself stays unchanged. UDP Custom uses the separate generated password described above. Dropbear,
SocksIP UDP, OpenVPN, WireGuard and Hysteria do not gain certificate support
from this feature. Readiness checks
reject gateways still routed to Dropbear; audit before issuing credentials.

The CA private key stays on the VPS and is never included in the bundle. The
exported account private key is intentionally portable: anyone with the bundle
can use that account in a compatible client. This is not app attestation or a
restriction exclusive to one APK. Existing device-generated certificate mode is
retained separately. Test real login, browsing and reconnects on each transport
before distributing production configurations.

## Sharing an original certificate across VPS servers

Use menu 08/09 or `shared-export` / `shared-import`, not the existing private-bundle import. See [Shared certificate accounts](SHARED-CERTIFICATE-ACCOUNTS.md) for A/B/C setup, per-destination host pins and coordinated renewal/revocation.

## Separate account management

SSH Account Management lists, renews and deletes password accounts only. Certificate
accounts remain Linux SSH identities internally but are hidden from that menu;
direct ordinary `ssh-accounts.sh delete NAME` and `renew NAME DAYS` refuse them too.
Existing certificate accounts are recognized from their identity database, private
bundle or certificate-only policy without recreating them. New accounts carry an
explicit accountType marker, including incomplete certificate setup.

Certificate menu 11 explicitly deletes a certificate account and ALL its local and
shared identities on this VPS after confirmation. Revocation (03/10) removes the
selected credential without deleting the Linux account. Deletion does not remove
copies on another VPS. Use `ssh-accounts.sh list-certificate` to list managed Linux
certificate accounts, including incomplete accounts without an issued bundle.
Automatic expired-account cleanup still covers both types; this separation protects
manual SSH menu operations, not expired accounts. No already deleted account or
private certificate key is automatically restored by this update.

Separation tests use the real classifier, shell dispatch and jq against temporary
stores. Linux user operations, permissions and locking are mocked on Windows;
verify list/renew/delete behavior on a live VPS after refreshing the menu.

Existing-account actions use numbered lists. Certificate lists identify local/shared
origin and a short identity ID when usernames repeat. Renew and private Gen export
show locally issued accounts; shared-authorization removal shows shared identities.
Create/import still ask for the new username. Back (0/00), invalid selections and EOF do not run the selected action or require
an extra pause. Empty lists and loading errors remain visible until Enter is pressed.
Renewal lists only locally issued private bundles; shared authorizations are renewed
on their original issuing VPS and then re-imported.

## Saved proxy exports

Option 12 shows this VPS's public proxy IP/key/fingerprint JSON without needing
an account. Option 13 pastes and saves it on another VPS. Option 05 then offers
Direct or Saved proxy; only the exported copy's SSHHostKeyPin changes. Public
account authorization (08/09) is still required on the proxy. See
[Shared certificate accounts](SHARED-CERTIFICATE-ACCOUNTS.md) for the A/B/C steps.

After deleting a certificate account, its username can be used again for a new
certificate account. ENG retains the old revoked identity as history and issues a
fresh key and identity; it never restores the old certificate. Export the new Gen
bundle and re-share its public authorization where needed. If an earlier failed
creation left an incomplete Linux account, remove it with certificate menu 11,
then create again. Do not remove revoked database records manually.
