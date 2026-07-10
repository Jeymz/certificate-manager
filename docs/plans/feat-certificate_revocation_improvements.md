# Feat: Certificate Revocation Improvements

## Goals

- Add `cRLDistributionPoints` to leaf and intermediate profiles.
- Add `cRLSign` to the issuer cert profile that will sign the CRL.
- Stop requiring the CA passphrase for CRL retrieval by clients.
- Generate the CRL ahead of time and publish it as a static artifact, rather than unlocking the CA key on every GET.
- Reissue certificates after the new extensions are in place. Existing certs will not gain CDP/AIA retroactively.

## Current State

- Certificate extensions are sourced from config and applied during signing in `src/resources/ca.js`.
- Active runtime verification with `certutil -dump` on `nas01.robotti.private.cert.crt` confirmed newly issued leaf certificates still do not contain `2.5.29.31` (`cRLDistributionPoints`).
- `GET /crl.pem` currently generates a CRL on demand and requires `x-ca-passphrase`, which makes it unsuitable as a CRL Distribution Point for Windows or other automated TLS clients.
- CRL numbers are already persisted through `src/resources/crlNumber.js`, and revocation state is already tracked in `src/resources/revocation.js`.
- The default configuration allows issuing leaf certificates directly from the root CA, so the issuer profile used for CRL signing must be handled carefully.
- The root CA created by `scripts/setup.js` does not currently include a `keyUsage` extension with `cRLSign`, so root-issued deployments need setup-time changes in addition to config profile changes.
- Automatic CRL republishing after revoke cannot be implemented with the current `/revoke` payload because the service still needs CA private-key access to sign a fresh CRL.

## Desired Outcome

- Newly issued leaf and intermediate certificates embed a stable CRL Distribution Point URL.
- The CA or intermediate that signs revocation lists is explicitly allowed to sign CRLs via `cRLSign`.
- The application publishes a pre-generated static CRL artifact that clients can fetch without credentials.
- Revocation updates trigger CRL regeneration so published data stays current.
- Documentation makes the operational requirement clear: existing certificates must be reissued to gain the new CDP metadata.

## Proposed Design

### 1. Configuration Model

- Extend certificate extension configuration to support `cRLDistributionPoints` entries for `webServer`, `ldapServer`, and `intermediateCA`.
- Add a new configuration section for revocation publishing, for example:
  - CRL public URL
  - CRL output filename/path under the certificate store
  - optional enable/disable toggle for published CRL generation
- Add `cRLSign: true` to the issuer profile that is expected to sign the CRL:
  - `CA` when issuing directly from the root
  - `intermediateCA` when using an intermediate to issue leaves
- Keep the model environment-driven and container-friendly by deriving filesystem locations from the existing store directory.

### 2. Certificate Signing Path

- Update `src/resources/ca.js` only as needed to ensure the configured CRL distribution point extension is emitted cleanly for supported profiles.
- Preserve the current pattern where extensions come from centralized config rather than being assembled ad hoc in service code.
- Confirm that SAN merging behavior continues to work when the profile contains additional X.509 extensions.

### 3. CRL Generation Lifecycle

- Refactor `src/services/crlService.js` so CRL creation is a reusable internal operation and CRL publication is a separate write step.
- Generate the signed CRL after revocation changes rather than during client reads.
- Persist the generated CRL to a predictable store location, such as `<storeDirectory>/crl/<issuer>.crl.pem`.
- Continue using the existing CRL number store so each published CRL advances monotonically.
- Publish an initial empty CRL during root CA setup and during configured intermediate setup so Windows clients can fetch revocation state before the first revoke event.

### 4. HTTP Surface

- Change `GET /crl.pem` from dynamic generation to static retrieval of the published artifact.
- Remove the `x-ca-passphrase` requirement from CRL retrieval.
- Return a clear error when CRL publication is enabled but no CRL has been generated yet.
- Keep `GET /crl` as the JSON inspection endpoint for operators unless there is a separate decision to reduce exposure.
- Update `/revoke` to require the CA passphrase so the service can sign and publish the refreshed CRL atomically with the revocation change.

### 5. Setup And Operational Flow

- Update setup flow so a baseline CRL can be generated once the CA or intermediate exists.
- Provide a manual CRL publication script for already-initialized CA stores so operators do not need to recreate the CA just to backfill the first static CRL artifact.
- If the project supports both root-issued and intermediate-issued leaf certs, document which issuer's URL should be embedded in each profile.
- Document the homelab runtime expectation:
  - publish the CRL on a stable hostname reachable by Windows clients
  - prefer plain HTTP for CRL distribution to avoid TLS bootstrap problems
  - trust the root CA in the Windows certificate store

## Implementation Steps

1. Done: extend config examples and runtime config accessors for CRL publication settings and CDP extension values.
2. Done: finish issuer profile updates needed for CRL signing coverage, including root setup-time `keyUsage`/`cRLSign` for root-issued deployments.
3. Done: add config accessors and validation support in `src/resources/config.js` for the new revocation publishing settings.
4. Done: refactor `src/services/crlService.js` to support:
   - generating a CRL payload
   - writing the CRL artifact to disk
   - loading the published CRL artifact for HTTP responses
5. Done: update revocation flow so successful `revoke` operations regenerate and publish the CRL, including the required revoke payload change to carry the CA passphrase.
6. Done: update `src/routers/certRouter.js` and `src/controllers/certController.js` so `GET /crl.pem` serves the published artifact without requiring the CA passphrase.
7. Done: update setup scripts to create the first CRL artifact for the active issuer.
8. Done: update `readme.md` with the new runtime model, CRL publication requirements, revoke payload change, and reissuance guidance.

## Affected Files

- `config/defaults.json`
- `config/defaults.example.json`
- `src/resources/config.js`
- `src/resources/ca.js`
- `src/services/crlService.js`
- `src/controllers/certController.js`
- `src/routers/certRouter.js`
- `scripts/setup.js`
- `scripts/setup-intermediate.js`
- `readme.md`
- `tests/crlService.test.js`
- `tests/certRouter.test.js`
- `tests/certController.test.js`
- `tests/ca.test.js`
- additional config or setup tests if new accessors are introduced

## Validation Plan

- Unit-test CRL generation and publication separately from HTTP retrieval.
- Add router tests proving `GET /crl.pem` no longer requires `x-ca-passphrase`.
- Add tests proving revocation triggers CRL publication.
- Add tests confirming configured CRL Distribution Point extensions are present on newly issued leaf and intermediate certificates.
- Add tests confirming issuer profiles include `cRLSign` where expected.
- Manually verify on Windows with:
  - `certutil -url <certfile>`
  - `curl.exe https://<host>` without `--ssl-no-revoke` after reissuing against the new profile

## Risks And Open Decisions

- Root-issued and intermediate-issued deployments need a clear issuer model; otherwise the wrong CRL URL or signing profile may be applied.
- Publishing CRLs from the app introduces a file artifact lifecycle that setup, revocation, and container storage all need to agree on.
- If the CRL artifact is not generated during setup, clients may fail revocation checks until the first revoke event or manual publication.
- Existing certificates will continue to fail revocation lookup expectations until they are reissued with the new CDP extension.
- `GET /crl` currently exposes revocation inventory; this plan leaves it unchanged, but that endpoint may deserve a separate hardening decision.

## Out Of Scope

- OCSP responder support
- Reworking the overall auth model for revocation and CRL inspection
- Full PKI hierarchy redesign beyond the minimum needed to support a publishable CRL
