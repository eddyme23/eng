# One certificate account for direct and proxy connections

Each destination keeps its own account. For example, B has `muslim`, C has
`edozprodoings`, and A accepts both public authorizations alongside its own
accounts. Neither the username nor private SSH host keys need to be shared across
all servers. A still needs a local Linux identity for every account it authenticates.

## Export one current-format bundle

1. Update ENG on A and the destinations with git pull and refresh-menu-v6.sh.
2. On A, App Certificate Accounts **06 -> 04**: copy the public proxy JSON.
3. On B/C, **06 -> 05**: paste A's details once.
4. Create or keep the account on its original destination VPS.
5. Use **06 -> 01** on that VPS and **06 -> 02** on A to authorize that account on A.
6. Use **05 -> 02** on the destination and select its account. Both host approvals are included automatically.
7. Paste that one private JSON bundle into the updated matching Gen, export its
   protected configuration, and use the updated app.

That bundle works directly on the destination and with A as the SSH endpoint.
Your app/profile still selects the direct or proxy connection path. It does not
connect to both servers at once or make A route traffic through B/C automatically.

```bash
cd /root/eng
git pull --ff-only origin main
bash ./refresh-menu-v6.sh
# Standard export automatically includes a saved proxy:
bash ./app-ssh-auth.sh bundle-export ACCOUNT
```

Fresh creation, renewal and standard export now use schema 2. The previous target
selector and export-mode flags have been removed. With no proxy saved, schema 2
contains one approved local host. Older stored bundles can still be read and are
upgraded on export without changing the account key, certificate or identity.

## Contract shared by ENG, Gen and the apps

Combined exports use schema **2**, keeping the same account certificate, key,
username, identity, expiry and CA. The primary `genPolicy.SSHHostKeyPin` stays the
destination's key. The new `genPolicy.SSHHostKeyPins` array explicitly approves the
primary and saved-proxy fingerprints, deduplicated. No persisted bundle is edited.

Updated TG, GT, GV and VC apps and Gens:

- accept the existing single-pin schema 1 and the new schema 2;
- require schema 2 to contain 1-8 distinct, valid fingerprints including the primary;
- preserve the complete list through parsing, normalization and protected Gen export;
- verify the actual SSH server against the approved set for account-certificate mode;
- retain single-pin verification for device certificates and existing account bundles;
- reject malformed lists, missing primary pins, duplicates and unknown host keys.

The external profile's primary host-pin and CA checks remain in force. Gen/app
credentials carry the new list inside the protected account bundle, without new JNI
preference keys. Password authentication and network routing are unchanged. UDP
Custom retains its existing generated-password behavior; the approved SSH host list
does not change its protocol authentication.

Use the updated app and Gen for all new exports. Older clients reject schema 2
rather than silently discarding its extra approvals. This is an SSH
user certificate feature, not TLS client-certificate/mTLS authentication.

## Renewal and revocation

Renew on the original issuer, re-export the combined bundle to Gen, and refresh
its public authorization on A if its authorization expiry needs extension. Revoke
each identity on every VPS that accepts it. Revocation is not background-synchronized.
When A's SSH host key changes, refresh saved proxy details and re-export the bundle.

## Validation

ENG certificate/policy and menu regression checks passed. All four apps and four
Gens compiled with :app:compileDebugJavaWithJavac. Existing real-SSH certificate,
password, forwarding and Gen contract checks passed.

The new TG native/tests/run_multi_host_certificate_checks.py runs the production
parsers and Session.verifyHost from each app/Gen pair against three loopback SSH
servers with different host keys and the actual ENG signer fixture. It verifies:

- one certificate signs in and forwards HTTP on both approved hosts over repeated reconnects;
- the third host is rejected, and a legacy single-pin bundle rejects the second host;
- invalid/oversized/duplicate/missing-primary lists are rejected;
- the approved set is immutable and survives protected Gen export/import.

Eight classpath runs passed 35 assertions each, with both app-first and Gen-first
parsers. Android logging, monotonic-clock and Base64 adapters are replaced in that
JDK harness; the SSH transport, signing, certificate parser and host verifier are
production code. Source copies remain identical across all eight parsers.

This does not establish device installation, real mobile-network behavior, live
VPS direct/proxy login or Play Store release readiness. No APK/AAB was published,
and app version codes/signing configuration were not changed by this work.
