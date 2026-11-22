# Certificate accounts on A and their original VPS servers

Create each certificate account on its destination VPS, then import its public
account authorization into proxy A. A can hold several separate usernames, while
each destination holds only the account(s) it needs. A also keeps its own accounts.

## Update existing servers

```bash
cd /root/eng
git pull --ff-only origin main
bash ./refresh-menu-v6.sh
```

Fresh installation uses these same current scripts. No special enable flag is needed.

## Set up proxy A once

1. On A, certificate menu **06 -> 04**: copy the public proxy JSON. No account is required.
2. On each destination VPS, **06 -> 05**: paste A's JSON. Import completes automatically.

A's SSH host key is read locally and checked against installed SSH configurations;
it is not learned by an unverified SSH network lookup. The IP is detected using
api.ipify.org. For a different public inbound IP, run on A:

```bash
bash ./app-ssh-auth.sh proxy-export --ip A_PUBLIC_IPV4
```

Only paste proxy details copied from your trusted A console. The public key and
fingerprint must match. Saving them changes no password accounts or SSH config.

## Share an account and export to Gen

1. Create or keep the certificate account on B/C using its own username.
2. Use **06 -> 01** there to export its PUBLIC account authorization.
3. Use **06 -> 02** on A and paste that authorization (no END needed).
4. Use **05 -> 02** on B/C, select the account, then copy the PRIVATE JSON into the updated Gen.

There is now just one export format. It always approves the local VPS's host key,
and automatically adds saved A's key if configured. With no saved proxy, it approves
only the local VPS. There is no Direct/Proxy/Combined selection and no mode flag.

```bash
bash ./app-ssh-auth.sh shared-export ACCOUNT > /root/account-public.json
bash ./app-ssh-auth.sh shared-import /root/account-public.json
bash ./app-ssh-auth.sh bundle-export ACCOUNT
```

The public account package contains no private key, CA private key, Gen bundle,
UDP password or server host key. Root explicitly trusts its CA for the named account
and principal only. Verify its origin before import; it is not a signed enrollment
token. Import never changes an ordinary password account. On an existing certificate
account, additional identities coexist without replacing the original bundle or CA.
Repeated imports of an active identity are safe; revoked identities and changed keys
are rejected. Each local authorization is capped by that VPS's Linux account expiry.

Your app still chooses the direct or proxy connection path. Host approvals do not
configure routing or make A automatically forward traffic through B/C. When A
terminates SSH, A authenticates the imported account and carries the traffic.

## Renewal, removal and expiry

Renew the private certificate on its issuing VPS, export updated JSON to Gen, and
re-import its public authorization into A if the authorization expiry needs extension.
To extend a replica's Linux account validity before re-importing:

```bash
bash ./ssh-accounts.sh renew-certificate ACCOUNT DAYS
```

Use **06 -> 03** to remove one shared identity, preserving the other identities under
that username. Menu **03** explicitly deletes the Linux account and all identities
on that VPS. Revocations must be applied on each server accepting the identity;
existing authenticated sessions are not terminated by credential revocation alone.

Default exports transparently upgrade previously stored account bundles to schema 2
without replacing their account, certificate, key or identity. New and renewed stored
bundles also use schema 2. Older private bundles remain readable for safe upgrades;
ENG no longer generates the older export variants. The updated app and Gen are required.
See [Protocol and validation details](MULTI-HOST-CERTIFICATES.md).

Saved proxy commands:

```bash
bash ./app-ssh-auth.sh proxy-export
bash ./app-ssh-auth.sh proxy-save
bash ./app-ssh-auth.sh proxy-status
bash ./app-ssh-auth.sh proxy-clear
```

After clearing the preference, future exports approve only the local host. Previously
exported copies are unchanged; re-export and distribute new configurations as needed.
A host-key rotation similarly requires re-saving A's public details and re-exporting.

Local tests cover automatic export on fresh accounts, old-bundle upgrades, renewal,
three identities under one username, independent revocation, expiry caps and rollback.
All app/Gen pairs compiled and passed real loopback SSH/HTTP/reconnect checks against
two approved host keys, with a third key rejected. Device and VPS testing remains.
